package scanner

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/scanner/modules"
)

// Credential ordering modes for Options.Order.
const (
	// OrderPassword holds one password constant per round and walks every
	// username. This is the lockout-safe ordering and the default.
	OrderPassword = "password"
	// OrderUser holds one username constant per round and walks every
	// password. Fast, but it empties one account's lockout budget at a time.
	OrderUser = "user"
)

// sprayRound is one scheduling unit. Every credential in a round is attempted
// against every target before the run sleeps and moves on. With the default
// password ordering a round carries one password and every username, which is
// what holds each account to a single attempt per round.
type sprayRound struct {
	// Key is the value held constant for the whole round.
	Key   string
	Creds []modules.Credential
}

// buildSprayRounds groups the credential set into rounds keyed by password
// (default) or username. Duplicate pairs are dropped: in a lockout-sensitive
// run, trying the same pair twice spends budget for nothing.
func buildSprayRounds(usernames, passwords []string, combos []modules.Credential, order string) []sprayRound {
	all := make([]modules.Credential, 0, len(combos)+len(usernames)*len(passwords))
	all = append(all, combos...)
	if order == OrderUser {
		for _, user := range usernames {
			for _, pwd := range passwords {
				all = append(all, modules.Credential{Username: user, Password: pwd})
			}
		}
	} else {
		for _, pwd := range passwords {
			for _, user := range usernames {
				all = append(all, modules.Credential{Username: user, Password: pwd})
			}
		}
	}

	// Dedupe on the account rather than the raw username. "admin", "Admin" and
	// "CORP\admin" with the same password are one attempt against one
	// directory account, and trying each would quietly spend several of its
	// lockout attempts in a single round.
	seen := make(map[modules.Credential]struct{}, len(all))
	position := make(map[string]int)
	var rounds []sprayRound

	for _, cred := range all {
		folded := modules.Credential{Username: accountKey(cred.Username), Password: cred.Password}
		if _, dup := seen[folded]; dup {
			logger.Debugf("spray: skipping %q, the same account and password as an earlier entry", cred.Username)
			continue
		}
		seen[folded] = struct{}{}

		key := cred.Password
		if order == OrderUser {
			key = cred.Username
		}

		i, ok := position[key]
		if !ok {
			i = len(rounds)
			position[key] = i
			rounds = append(rounds, sprayRound{Key: key})
		}
		rounds[i].Creds = append(rounds[i].Creds, cred)
	}

	return rounds
}

// sprayUsernames lists the distinct accounts a campaign will touch, in first
// -seen order. Empty usernames are left out: modules that carry the secret in
// the password field have no account to lock out.
func sprayUsernames(rounds []sprayRound) []string {
	seen := make(map[string]struct{})
	var users []string
	for _, round := range rounds {
		for _, cred := range round.Creds {
			if cred.Username == "" {
				continue
			}
			if _, dup := seen[cred.Username]; dup {
				continue
			}
			seen[cred.Username] = struct{}{}
			users = append(users, cred.Username)
		}
	}
	return users
}

// accountKey folds a username down to the account it names.
//
// A wordlist routinely carries "admin", "Admin" and "CORP\admin", which are
// three strings but one Active Directory account with one lockout counter.
// Keying the budget on the raw string would hand that account three separate
// allowances and let it take several attempts in a single round.
func accountKey(username string) string {
	user := strings.TrimSpace(username)
	if i := strings.Index(user, `\`); i >= 0 {
		user = user[i+1:]
	}
	if i := strings.LastIndex(user, "@"); i > 0 {
		user = user[:i]
	}
	return strings.ToLower(user)
}

// AccountBudget enforces --max-attempts-per-user.
//
// The budget is global on purpose. Lockout counters live on the directory, not
// on the host you happen to be talking to, so a failed logon for one account
// against two domain controllers is two attempts against one counter. A run
// over N hosts therefore spends N attempts per account per round, which is why
// the cap counts across hosts rather than per host.
//
// It is exported so a caller that outlives a single run, such as the MCP
// server, can hold one budget across all of them instead of handing every
// account a fresh allowance on each call.
type AccountBudget struct {
	mu     sync.Mutex
	max    int
	used   map[string]int
	capped map[string]bool
}

// NewAccountBudget returns a budget allowing max attempts per account, or an
// unlimited one when max is zero or less.
func NewAccountBudget(max int) *AccountBudget {
	return &AccountBudget{
		max:    max,
		used:   make(map[string]int),
		capped: make(map[string]bool),
	}
}

// reserve claims one attempt for username and reports whether it was granted.
//
// Budget is taken before the attempt is dispatched, so anything that then does
// not get attempted must be handed back with refund, or the campaign will stop
// believing accounts are spent when they are not.
//
// An empty username is never charged: modules such as snmp and vnc carry the
// secret in the password field and have no account to lock.
func (b *AccountBudget) reserve(username string) bool {
	if b == nil || b.max <= 0 || username == "" {
		return true
	}
	key := accountKey(username)
	if key == "" {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.used[key] >= b.max {
		return false
	}
	b.used[key]++

	if b.used[key] >= b.max && !b.capped[key] {
		b.capped[key] = true
		logger.Failf("per-user attempt limit of %d reached for %q, no further attempts for this account",
			b.max, key)
	}
	return true
}

// refund hands back a reservation whose attempt never happened, so that a
// round cut short by cancellation or --stop-on-success does not leave accounts
// looking spent when they are not.
func (b *AccountBudget) refund(username string) {
	if b == nil || b.max <= 0 || username == "" {
		return
	}
	key := accountKey(username)
	if key == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.used[key] > 0 {
		b.used[key]--
	}
	if b.used[key] < b.max {
		delete(b.capped, key)
	}
}

// Max reports the configured per-account maximum, 0 meaning unlimited.
func (b *AccountBudget) Max() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.max
}

// remaining reports how many of the given accounts still have budget left.
func (b *AccountBudget) remaining(usernames []string) int {
	if b == nil || b.max <= 0 {
		return len(usernames)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var n int
	for _, user := range usernames {
		key := accountKey(user)
		if key == "" || b.used[key] < b.max {
			n++
		}
	}
	return n
}

// RunSpray executes a lockout-safe spraying campaign for a single module.
//
// It differs from Run in two ways that matter against live Active Directory:
// every target is resolved up front so one password can be tried against all
// of them before the next password starts, and no attempt is ever made with a
// real account's credentials outside the scheduled rounds.
func (s *Scanner) RunSpray(ctx context.Context, command, targets string) error {
	module, ok := modules.Modules[command]
	if !ok {
		return errors.New("invalid command")
	}
	s.Opts.Command = command

	s.loadCredentials()
	collapseForEnum(s.Opts, &module)

	// Streaming targets is incompatible with spray ordering: a round is only
	// safe if every host is tried with the current password before the next
	// one starts, which needs the full target list in hand.
	all, err := s.collectTargets(ctx, module.DefaultPort, targets)
	if err != nil {
		return err
	}
	if len(all) == 0 {
		return errors.New("no usable targets to spray")
	}
	s.TargetCount = int64(len(all))

	if len(all) < s.Opts.Parallel {
		s.Opts.Parallel = len(all)
	}

	rounds := buildSprayRounds(s.Opts.UsernameList, s.Opts.PasswordList, s.Opts.ComboList, s.Opts.Order)
	if len(rounds) == 0 {
		return errors.New("no credentials to spray")
	}

	var totalCreds int64
	for _, round := range rounds {
		totalCreds += int64(len(round.Creds))
	}

	// Accounts actually in scope, taken from the credential set rather than
	// the username list, so combo files and credential mutations count too.
	users := sprayUsernames(rounds)

	if !logger.IsQuiet() {
		s.printDashboard(dashboardConfig{
			Module:      command,
			Targets:     targets,
			HostCount:   len(all),
			SprayRounds: len(rounds),
			SprayCreds:  int(totalCreds),
		})
	}

	// A caller that outlives a single run, such as the MCP server, supplies
	// its own budget so repeated runs cannot each hand every account a fresh
	// allowance.
	budget := s.Opts.AccountBudget
	if budget == nil {
		budget = NewAccountBudget(s.Opts.MaxAttemptsPerUser)
	}

	var progress *Progress
	if !logger.IsQuiet() && !s.Opts.NoStats {
		progress = NewProgress(s, totalCreds, s.TargetCount)
		logger.SetProgressClearer(progress.Clear)
		progress.Start()
	}

	var resultsWg sync.WaitGroup
	resultsWg.Add(1)
	go GetResults(s.Results, s.Opts.OutputFile, &resultsWg, s.Successes, s.Opts.JSON)

	live := s.probeTargets(ctx, &module, all)
	if len(live) == 0 {
		logger.Infof("no targets responded, nothing to spray")
	}

	// Worth saying out loud: the lockout counter is on the directory, so every
	// extra host multiplies what a round costs each account.
	if budget.Max() > 0 && len(live) > 1 {
		logger.Infof("spraying %d hosts, so each round costs %d attempt(s) per account; the limit of %d covers %d full round(s)",
			len(live), len(live), budget.Max(), budget.Max()/len(live))
	}

	for i, round := range rounds {
		if ctx.Err() != nil {
			break
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			break
		}
		if len(live) == 0 {
			break
		}

		logger.Infof("spray round %d/%d: %s=%q across %d credential(s) and %d host(s)",
			i+1, len(rounds), s.orderLabel(), round.Key, len(round.Creds), len(live))

		dispatched := s.runSprayRound(ctx, &module, live, round, budget)

		// A round boundary is the natural place to make the checkpoint
		// durable: the next thing that happens is a long sleep.
		s.Opts.State.Flush()
		logger.Debugf("spray round %d dispatched %d attempt(s)", i+1, dispatched)

		// Abort on the budget itself, not on an empty round: a round can also
		// come out empty because --resume already covered it or because every
		// host had been solved, and neither means the accounts are spent.
		if s.Opts.MaxAttemptsPerUser > 0 && len(users) > 0 && budget.remaining(users) == 0 {
			logger.Failf("spray aborted: every account has reached the per-user attempt limit of %d",
				s.Opts.MaxAttemptsPerUser)
			break
		}

		if i < len(rounds)-1 && !s.sprayPause(ctx) {
			break
		}
	}

	close(s.Results)
	resultsWg.Wait()

	if progress != nil {
		progress.Stop()
		logger.SetProgressClearer(nil)
	}

	s.Stop()

	logger.Infof("Done: %d credential pairs tried, %d successful logins found",
		s.Attempts.Load(), s.Successes.Load())

	if s.Opts.MaxAttemptsPerUser > 0 && len(users) > 0 {
		logger.Infof("%d of %d accounts still had attempt budget left",
			budget.remaining(users), len(users))
	}

	if ctx.Err() != nil {
		logger.Infof("Interrupted")
	}

	return nil
}

// orderLabel describes what is held constant per round, for log output.
func (s *Scanner) orderLabel() string {
	if s.Opts.Order == OrderUser {
		return "user"
	}
	return "password"
}

// collectTargets drains the whole target source into a slice.
func (s *Scanner) collectTargets(ctx context.Context, defaultPort int, targets string) ([]*modules.Target, error) {
	ch := make(chan *modules.Target, BufferMultiplier)
	go SendTargets(ctx, ch, defaultPort, targets)

	var all []*modules.Target
	for target := range ch {
		all = append(all, target)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return all, nil
}

// probeTargets checks reachability and TLS support for every target, keeping
// the ones that answered. Unlike probe, it never submits the module's default
// credentials: that would spend a real account's lockout budget before the
// first scheduled round.
func (s *Scanner) probeTargets(ctx context.Context, module *modules.Module, all []*modules.Target) []*modules.Target {
	var (
		mu   sync.Mutex
		live []*modules.Target
		wg   sync.WaitGroup
	)

	sem := make(chan struct{}, s.Opts.Parallel)
	for _, target := range all {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(target *modules.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			s.annotateTarget(target)

			if !s.probeReachable(ctx, module, target) {
				return
			}
			mu.Lock()
			live = append(live, target)
			mu.Unlock()
		}(target)
	}
	wg.Wait()

	// Preserve input order so round logs are stable across runs.
	order := make(map[*modules.Target]int, len(all))
	for i, target := range all {
		order[target] = i
	}
	sortTargets(live, order)

	logger.Debugf("%d of %d targets responded", len(live), len(all))
	return live
}

// probeReachable authenticates as a random non-existent principal to learn
// whether the service answers and whether it speaks TLS. A username that does
// not exist cannot be locked out, so this costs no budget.
func (s *Scanner) probeReachable(ctx context.Context, module *modules.Module, target *modules.Target) bool {
	cred := s.anonymousProbeCredential()

	if _, err := module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred); err == nil {
		return true
	}

	logger.Debugf("%s did not answer with encryption, trying plaintext", target.Addr())
	target.Encryption = false

	_, err := module.Handler(ctx, s.Opts.ProxyDialer, s.Opts.Timeout, target, cred)
	if err == nil {
		return true
	}

	// Report the reason: a module that rejected the probe for a configuration
	// reason, such as a missing realm, is not the same as an unreachable host,
	// and "no targets responded" on its own sends people hunting a firewall.
	logger.Debugf("%s dropped from the spray: %v", target.Addr(), err)
	return false
}

// runSprayRound tries every credential in the round against every live target
// and returns how many attempts were dispatched. A return of zero while
// --max-attempts-per-user is set means no account has budget left.
func (s *Scanner) runSprayRound(
	ctx context.Context,
	module *modules.Module,
	live []*modules.Target,
	round sprayRound,
	budget *AccountBudget,
) int64 {
	var (
		dispatched atomic.Int64
		wg         sync.WaitGroup
	)

	sem := make(chan struct{}, s.Opts.Parallel)

	for _, target := range live {
		if ctx.Err() != nil {
			break
		}
		if s.Opts.GlobalStop && s.globalDone.Load() {
			break
		}
		if s.Opts.StopOnSuccess && targetSucceeded(target) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(target *modules.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			credCh := make(chan *modules.Credential, s.Opts.Threads*BufferMultiplier)
			done := make(chan struct{})

			go func() {
				defer close(credCh)
				for _, cred := range round.Creds {
					// Check the checkpoint before the budget: a resumed run
					// must not spend an account's remaining attempts on pairs
					// it already tried.
					if s.Opts.State.Done(target.OriginalTarget, s.Opts.Command, cred.Username, cred.Password) {
						continue
					}
					if !budget.reserve(cred.Username) {
						continue
					}
					cred := cred
					select {
					case credCh <- &cred:
						dispatched.Add(1)
					case <-done:
						budget.refund(cred.Username)
						return
					case <-ctx.Done():
						budget.refund(cred.Username)
						return
					}
				}
			}()

			var threadWg sync.WaitGroup
			for i := 0; i < s.Opts.Threads; i++ {
				threadWg.Add(1)
				go s.ThreadHandler(ctx, &threadWg, credCh, module.Handler, target)
			}
			threadWg.Wait()
			close(done)

			// Credentials still queued when the workers stopped were charged
			// to their account but never tried. Hand the budget back, or a run
			// cut short by --stop-on-success or cancellation would report
			// accounts as spent and abort the campaign early.
			for cred := range credCh {
				budget.refund(cred.Username)
				dispatched.Add(-1)
			}
		}(target)
	}

	wg.Wait()
	return dispatched.Load()
}

// sprayPause waits --delay with a random offset of up to --jitter either way.
// It reports false when the run was cancelled while waiting.
func (s *Scanner) sprayPause(ctx context.Context) bool {
	wait := s.Opts.Delay + jitterOffset(s.Opts.Jitter)
	if wait <= 0 {
		return ctx.Err() == nil
	}

	// Round to whole seconds only when the wait is long enough for that to
	// read better than the raw value.
	shown := wait
	if shown >= 10*time.Second {
		shown = shown.Round(time.Second)
	}
	logger.Infof("spray round complete, sleeping %s", shown)

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// jitterOffset returns a uniform random duration in [-jitter, +jitter].
func jitterOffset(jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(jitter)*2+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64() - int64(jitter))
}

// randomPrincipal returns a username no directory is likely to hold.
func randomPrincipal() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

	b := make([]byte, 16)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return fmt.Sprintf("bruter-probe-%d", time.Now().UnixNano())
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

// targetSucceeded reads Target.Success under its mutex.
func targetSucceeded(target *modules.Target) bool {
	target.Mutex.Lock()
	defer target.Mutex.Unlock()
	return target.Success
}

// sortTargets orders targets by their original position. Hosts arrive here in
// whatever order they finished answering the probe, which on a large range is
// tens of thousands of entries, so this cannot be a quadratic sort.
func sortTargets(targets []*modules.Target, position map[*modules.Target]int) {
	sort.Slice(targets, func(i, j int) bool {
		return position[targets[i]] < position[targets[j]]
	})
}
