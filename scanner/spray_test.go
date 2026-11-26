package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vflame6/bruter/scanner/modules"
	"github.com/vflame6/bruter/utils"
)

// --- buildSprayRounds ---

func TestBuildSprayRoundsPasswordOrder(t *testing.T) {
	rounds := buildSprayRounds([]string{"alice", "bob"}, []string{"Autumn2026", "Winter2026"}, nil, OrderPassword)

	if len(rounds) != 2 {
		t.Fatalf("got %d rounds, want 2 (one per password): %+v", len(rounds), rounds)
	}
	if rounds[0].Key != "Autumn2026" || rounds[1].Key != "Winter2026" {
		t.Fatalf("round keys = %q, %q; want the passwords in wordlist order", rounds[0].Key, rounds[1].Key)
	}
	for i, round := range rounds {
		if len(round.Creds) != 2 {
			t.Fatalf("round %d holds %d creds, want one per username", i, len(round.Creds))
		}
		for _, cred := range round.Creds {
			if cred.Password != round.Key {
				t.Errorf("round %d (%q) contains password %q: a round must hold one password",
					i, round.Key, cred.Password)
			}
		}
	}
}

func TestBuildSprayRoundsUserOrder(t *testing.T) {
	rounds := buildSprayRounds([]string{"alice", "bob"}, []string{"p1", "p2", "p3"}, nil, OrderUser)

	if len(rounds) != 2 {
		t.Fatalf("got %d rounds, want 2 (one per username)", len(rounds))
	}
	if rounds[0].Key != "alice" || rounds[1].Key != "bob" {
		t.Fatalf("round keys = %q, %q; want usernames", rounds[0].Key, rounds[1].Key)
	}
	for i, round := range rounds {
		if len(round.Creds) != 3 {
			t.Fatalf("round %d holds %d creds, want one per password", i, len(round.Creds))
		}
		for _, cred := range round.Creds {
			if cred.Username != round.Key {
				t.Errorf("round %d (%q) contains username %q", i, round.Key, cred.Username)
			}
		}
	}
}

func TestBuildSprayRoundsDropsDuplicatePairs(t *testing.T) {
	// The combo list already carries alice:p1, so the matrix must not repeat it:
	// a duplicate attempt spends lockout budget and learns nothing.
	combos := []modules.Credential{{Username: "alice", Password: "p1"}}
	rounds := buildSprayRounds([]string{"alice", "bob"}, []string{"p1"}, combos, OrderPassword)

	var total int
	for _, round := range rounds {
		total += len(round.Creds)
	}
	if total != 2 {
		t.Fatalf("got %d attempts, want 2 (alice:p1 once, bob:p1 once)", total)
	}
	if len(rounds) != 1 {
		t.Fatalf("got %d rounds, want 1: combo and matrix share password p1", len(rounds))
	}
}

func TestBuildSprayRoundsEmptyInput(t *testing.T) {
	if rounds := buildSprayRounds(nil, nil, nil, OrderPassword); len(rounds) != 0 {
		t.Fatalf("got %d rounds from empty input, want 0", len(rounds))
	}
}

// --- userBudget ---

func TestUserBudgetEnforcesCap(t *testing.T) {
	b := NewAccountBudget(2)

	for i := 0; i < 2; i++ {
		if !b.reserve("alice") {
			t.Fatalf("attempt %d for alice was refused while under the cap", i+1)
		}
	}
	if b.reserve("alice") {
		t.Error("third attempt for alice was granted despite a cap of 2")
	}
	if !b.reserve("bob") {
		t.Error("bob was refused budget because alice ran out: the cap is per account")
	}
}

func TestUserBudgetUnlimitedWhenZero(t *testing.T) {
	b := NewAccountBudget(0)
	for i := 0; i < 100; i++ {
		if !b.reserve("alice") {
			t.Fatalf("attempt %d refused with the cap disabled", i+1)
		}
	}
}

func TestUserBudgetIgnoresEmptyUsername(t *testing.T) {
	// snmp and vnc carry the secret in the password field; there is no account
	// to lock, so an empty username must never exhaust the budget.
	b := NewAccountBudget(1)
	for i := 0; i < 10; i++ {
		if !b.reserve("") {
			t.Fatalf("attempt %d with an empty username was refused", i+1)
		}
	}
}

func TestUserBudgetRemaining(t *testing.T) {
	b := NewAccountBudget(1)
	users := []string{"alice", "bob", "carol"}

	if got := b.remaining(users); got != 3 {
		t.Fatalf("remaining = %d before any attempt, want 3", got)
	}
	b.reserve("alice")
	if got := b.remaining(users); got != 2 {
		t.Fatalf("remaining = %d after capping alice, want 2", got)
	}
	b.reserve("bob")
	b.reserve("carol")
	if got := b.remaining(users); got != 0 {
		t.Fatalf("remaining = %d after capping everyone, want 0", got)
	}
}

func TestUserBudgetConcurrentReserveRespectsCap(t *testing.T) {
	const cap = 50
	b := NewAccountBudget(cap)

	var granted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.reserve("alice") {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()

	if granted.Load() != cap {
		t.Fatalf("granted %d attempts under a cap of %d", granted.Load(), cap)
	}
}

// --- jitter ---

func TestJitterOffsetWithinBounds(t *testing.T) {
	const jitter = 5 * time.Minute
	for i := 0; i < 500; i++ {
		got := jitterOffset(jitter)
		if got < -jitter || got > jitter {
			t.Fatalf("jitterOffset = %s, outside +/-%s", got, jitter)
		}
	}
}

func TestJitterOffsetZero(t *testing.T) {
	if got := jitterOffset(0); got != 0 {
		t.Fatalf("jitterOffset(0) = %s, want 0", got)
	}
}

// --- option validation ---

func TestNewScannerSprayOptionValidation(t *testing.T) {
	base := func() *Options {
		return &Options{ConcurrentServices: 1, Parallel: 1, Threads: 1, Timeout: time.Second}
	}

	t.Run("order defaults to password", func(t *testing.T) {
		opts := base()
		s, err := NewScanner(opts)
		if err != nil {
			t.Fatalf("NewScanner: %v", err)
		}
		if s.Opts.Order != OrderPassword {
			t.Fatalf("Order = %q, want %q", s.Opts.Order, OrderPassword)
		}
	})

	t.Run("rejects unknown order", func(t *testing.T) {
		opts := base()
		opts.Order = "sideways"
		if _, err := NewScanner(opts); err == nil {
			t.Fatal("expected an error for an unknown --order value")
		}
	})

	t.Run("rejects jitter larger than delay", func(t *testing.T) {
		opts := base()
		opts.Delay = time.Minute
		opts.Jitter = 2 * time.Minute
		if _, err := NewScanner(opts); err == nil {
			t.Fatal("expected an error: jitter exceeding delay can only produce a negative wait")
		}
	})

	t.Run("rejects negative max attempts", func(t *testing.T) {
		opts := base()
		opts.MaxAttemptsPerUser = -1
		if _, err := NewScanner(opts); err == nil {
			t.Fatal("expected an error for a negative --max-attempts-per-user")
		}
	})
}

// --- RunSpray ---

// recorder captures every credential a module handler is asked to try.
type recorder struct {
	mu      sync.Mutex
	entries []recordedAttempt
}

type recordedAttempt struct {
	Target   string
	Username string
	Password string
}

func (r *recorder) handler() modules.ModuleHandler {
	return func(_ context.Context, _ *utils.ProxyAwareDialer, _ time.Duration, target *modules.Target, cred *modules.Credential) (bool, error) {
		r.mu.Lock()
		r.entries = append(r.entries, recordedAttempt{
			Target:   target.Addr(),
			Username: cred.Username,
			Password: cred.Password,
		})
		r.mu.Unlock()
		return false, nil
	}
}

func (r *recorder) snapshot() []recordedAttempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedAttempt, len(r.entries))
	copy(out, r.entries)
	return out
}

// registerTestModule installs a module in the global registry for the duration
// of a test.
func registerTestModule(t *testing.T, name string, module modules.Module) {
	t.Helper()
	if _, exists := modules.Modules[name]; exists {
		t.Fatalf("module %q already exists; pick a name that cannot collide", name)
	}
	modules.Modules[name] = module
	t.Cleanup(func() { delete(modules.Modules, name) })
}

func newSprayScanner(opts *Options) *Scanner {
	s := newTestScanner(opts)
	// RunSpray drains Results itself, so give it room for the whole run.
	s.Results = make(chan *Result, 256)
	return s
}

func TestRunSprayFinishesEachPasswordBeforeTheNext(t *testing.T) {
	rec := &recorder{}
	registerTestModule(t, "spraytest-order", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	s := newSprayScanner(&Options{
		Parallel: 2, Threads: 2, Timeout: time.Second,
		Delay:        time.Millisecond,
		Order:        OrderPassword,
		Spray:        true,
		NoStats:      true,
		UsernameList: []string{"alice", "bob", "carol"},
		PasswordList: []string{"p1", "p2", "p3"},
	})

	if err := s.RunSpray(context.Background(), "spraytest-order", "127.0.0.1:9,127.0.0.2:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	users := map[string]bool{"alice": true, "bob": true, "carol": true}

	// The guarantee: once a later password appears, no earlier one may come
	// back — across every host, not just within one.
	var order []string
	seen := make(map[string]bool)
	for _, entry := range rec.snapshot() {
		if !users[entry.Username] {
			continue // reachability probe, checked separately
		}
		if !seen[entry.Password] {
			seen[entry.Password] = true
			order = append(order, entry.Password)
			continue
		}
		if entry.Password != order[len(order)-1] {
			t.Fatalf("password %q was retried after the spray moved on to %q; rounds overlapped",
				entry.Password, order[len(order)-1])
		}
	}

	if len(order) != 3 {
		t.Fatalf("observed %d distinct passwords (%v), want 3", len(order), order)
	}
	for i, want := range []string{"p1", "p2", "p3"} {
		if order[i] != want {
			t.Errorf("round %d used password %q, want %q", i+1, order[i], want)
		}
	}
}

func TestRunSprayProbeNeverUsesRealAccounts(t *testing.T) {
	rec := &recorder{}
	registerTestModule(t, "spraytest-probe", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "Administrator", DefaultPassword: "Password1",
	})

	s := newSprayScanner(&Options{
		Parallel: 1, Threads: 1, Timeout: time.Second,
		Delay:        time.Millisecond,
		Order:        OrderPassword,
		Spray:        true,
		NoStats:      true,
		UsernameList: []string{"alice"},
		PasswordList: []string{"p1"},
	})

	if err := s.RunSpray(context.Background(), "spraytest-probe", "127.0.0.1:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	// The probe must not spend Administrator's lockout budget to learn that a
	// host is up.
	for _, entry := range rec.snapshot() {
		if entry.Username == "Administrator" {
			t.Fatalf("the reachability probe authenticated as %q, which can lock a real account", entry.Username)
		}
	}
}

func TestRunSprayHonoursMaxAttemptsPerUser(t *testing.T) {
	rec := &recorder{}
	registerTestModule(t, "spraytest-budget", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	s := newSprayScanner(&Options{
		Parallel: 2, Threads: 1, Timeout: time.Second,
		Delay:              time.Millisecond,
		Order:              OrderPassword,
		Spray:              true,
		NoStats:            true,
		MaxAttemptsPerUser: 1,
		UsernameList:       []string{"alice", "bob"},
		PasswordList:       []string{"p1", "p2", "p3", "p4"},
	})

	// Two hosts and four passwords would be 8 attempts per account without a
	// cap. The cap is global, so each account may be tried exactly once in the
	// whole run — including across hosts, because lockout counters are not
	// per-host.
	if err := s.RunSpray(context.Background(), "spraytest-budget", "127.0.0.1:9,127.0.0.2:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	perUser := map[string]int{}
	for _, entry := range rec.snapshot() {
		if entry.Username == "alice" || entry.Username == "bob" {
			perUser[entry.Username]++
		}
	}

	for _, user := range []string{"alice", "bob"} {
		if perUser[user] > 1 {
			t.Errorf("%s was tried %d times under --max-attempts-per-user 1", user, perUser[user])
		}
	}
}

func TestRunSprayRejectsUnknownModule(t *testing.T) {
	s := newSprayScanner(&Options{Parallel: 1, Threads: 1, Order: OrderPassword})
	if err := s.RunSpray(context.Background(), "definitely-not-a-module", "127.0.0.1"); err == nil {
		t.Fatal("expected an error for an unknown module")
	}
}

func TestRunSprayRejectsEmptyCredentialSet(t *testing.T) {
	rec := &recorder{}
	registerTestModule(t, "spraytest-nocreds", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
	})

	s := newSprayScanner(&Options{
		Parallel: 1, Threads: 1, Timeout: time.Second,
		Order:   OrderPassword,
		Spray:   true,
		NoStats: true,
	})

	if err := s.RunSpray(context.Background(), "spraytest-nocreds", "127.0.0.1:9"); err == nil {
		t.Fatal("expected an error when there are no credentials to spray")
	}
}

func TestSprayPauseReturnsOnCancel(t *testing.T) {
	s := newSprayScanner(&Options{Parallel: 1, Threads: 1, Delay: time.Hour})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if s.sprayPause(ctx) {
		t.Error("sprayPause reported success after cancellation")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("sprayPause slept %s after cancellation instead of returning", elapsed)
	}
}

func TestSendCredentialsUserOrder(t *testing.T) {
	users := []string{"alice", "bob"}
	passwords := []string{"p1", "p2"}

	creds := make(chan *modules.Credential, 10)
	done := make(chan struct{})
	SendCredentials(context.Background(), creds, users, passwords, nil, OrderUser, done)

	var got []modules.Credential
	for cred := range creds {
		got = append(got, *cred)
	}

	want := []modules.Credential{
		{Username: "alice", Password: "p1"},
		{Username: "alice", Password: "p2"},
		{Username: "bob", Password: "p1"},
		{Username: "bob", Password: "p2"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d creds, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("cred %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// --- account folding (review follow-up) ---

func TestAccountKeyFoldsToOneAccount(t *testing.T) {
	// These are five strings but one Active Directory account with one lockout
	// counter.
	want := accountKey("admin")
	for _, variant := range []string{"admin", "Admin", "ADMIN", `CORP\admin`, `corp\Admin`, "admin@corp.local", "Admin@CORP.LOCAL"} {
		if got := accountKey(variant); got != want {
			t.Errorf("accountKey(%q) = %q, want %q", variant, got, want)
		}
	}

	if accountKey("alice") == accountKey("bob") {
		t.Error("accountKey collapsed two different accounts")
	}
	if got := accountKey(""); got != "" {
		t.Errorf("accountKey(\"\") = %q, want empty", got)
	}
}

func TestBudgetCountsCaseVariantsAsOneAccount(t *testing.T) {
	b := NewAccountBudget(2)

	if !b.reserve("admin") {
		t.Fatal("first attempt for admin refused")
	}
	if !b.reserve("Admin") {
		t.Fatal("second attempt refused while under the cap")
	}
	// The cap is 2 and both variants charged the same account.
	if b.reserve(`CORP\admin`) {
		t.Error("a third attempt was granted; admin, Admin and CORP\\admin are one account")
	}
}

func TestBudgetRefundRestoresAllowance(t *testing.T) {
	b := NewAccountBudget(1)

	if !b.reserve("alice") {
		t.Fatal("first attempt refused")
	}
	if b.reserve("alice") {
		t.Fatal("second attempt granted under a cap of 1")
	}

	b.refund("alice")

	if !b.reserve("alice") {
		t.Error("after a refund the attempt was still refused; a cancelled round would strand the budget")
	}
	if got := b.remaining([]string{"alice"}); got != 0 {
		t.Errorf("remaining = %d after re-reserving, want 0", got)
	}
}

func TestBudgetRefundDoesNotGoNegative(t *testing.T) {
	b := NewAccountBudget(1)
	b.refund("alice")
	b.refund("alice")
	if !b.reserve("alice") {
		t.Fatal("reserve refused after spurious refunds")
	}
	if b.reserve("alice") {
		t.Error("the cap was exceeded, so refund drove the count below zero")
	}
}

func TestBuildSprayRoundsFoldsCaseVariants(t *testing.T) {
	rounds := buildSprayRounds([]string{"admin", "Admin", `CORP\admin`, "bob"}, []string{"p1"}, nil, OrderPassword)

	if len(rounds) != 1 {
		t.Fatalf("got %d rounds, want 1", len(rounds))
	}
	if len(rounds[0].Creds) != 2 {
		t.Fatalf("round holds %d creds (%+v), want 2: the admin variants are one account",
			len(rounds[0].Creds), rounds[0].Creds)
	}
}

func TestRunSprayStillTriesEveryHostInARound(t *testing.T) {
	// Folding accounts together must not be confused with folding hosts: one
	// password against three hosts is three attempts per account, and all
	// three have to happen.
	rec := &recorder{}
	registerTestModule(t, "spraytest-hosts", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	s := newSprayScanner(&Options{
		Parallel: 3, Threads: 1, Timeout: time.Second,
		Delay:        time.Millisecond,
		Order:        OrderPassword,
		Spray:        true,
		NoStats:      true,
		UsernameList: []string{"alice"},
		PasswordList: []string{"p1"},
	})

	if err := s.RunSpray(context.Background(), "spraytest-hosts", "127.0.0.1:9,127.0.0.2:9,127.0.0.3:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	hosts := map[string]bool{}
	for _, entry := range rec.snapshot() {
		if entry.Username == "alice" {
			hosts[entry.Target] = true
		}
	}
	if len(hosts) != 3 {
		t.Errorf("alice was tried on %d hosts (%v), want all 3", len(hosts), hosts)
	}
}

func TestRunSprayCapCountsAcrossHosts(t *testing.T) {
	// The lockout counter is domain-wide, so a cap of 2 over three hosts must
	// stop after two attempts, not allow two per host.
	rec := &recorder{}
	registerTestModule(t, "spraytest-crosshost", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	s := newSprayScanner(&Options{
		Parallel: 1, Threads: 1, Timeout: time.Second,
		Delay:              time.Millisecond,
		Order:              OrderPassword,
		Spray:              true,
		NoStats:            true,
		MaxAttemptsPerUser: 2,
		UsernameList:       []string{"alice"},
		PasswordList:       []string{"p1", "p2"},
	})

	if err := s.RunSpray(context.Background(), "spraytest-crosshost", "127.0.0.1:9,127.0.0.2:9,127.0.0.3:9"); err != nil {
		t.Fatalf("RunSpray: %v", err)
	}

	var attempts int
	for _, entry := range rec.snapshot() {
		if entry.Username == "alice" {
			attempts++
		}
	}
	if attempts > 2 {
		t.Errorf("alice was tried %d times under a cross-host cap of 2", attempts)
	}
}

func TestRunSprayWithSharedBudgetDoesNotResetPerRun(t *testing.T) {
	// An MCP client calling spray repeatedly must not get a fresh allowance
	// each time.
	rec := &recorder{}
	registerTestModule(t, "spraytest-shared", modules.Module{
		DefaultPort: 9, Handler: rec.handler(),
		DefaultUsername: "svc", DefaultPassword: "svc",
	})

	shared := NewAccountBudget(1)

	for run := 0; run < 3; run++ {
		s := newSprayScanner(&Options{
			Parallel: 1, Threads: 1, Timeout: time.Second,
			Delay:              time.Millisecond,
			Order:              OrderPassword,
			Spray:              true,
			NoStats:            true,
			MaxAttemptsPerUser: 1,
			AccountBudget:      shared,
			UsernameList:       []string{"alice"},
			PasswordList:       []string{"p1"},
		})
		if err := s.RunSpray(context.Background(), "spraytest-shared", "127.0.0.1:9"); err != nil {
			t.Fatalf("run %d: %v", run+1, err)
		}
	}

	var attempts int
	for _, entry := range rec.snapshot() {
		if entry.Username == "alice" {
			attempts++
		}
	}
	if attempts != 1 {
		t.Errorf("alice was tried %d times across 3 runs sharing a cap of 1, want 1", attempts)
	}
}
