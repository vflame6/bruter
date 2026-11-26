package modules

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/vflame6/bruter/logger"
	"github.com/vflame6/bruter/utils"
)

// maxKDCResponse caps a KDC reply. A real AS-REP carrying a Windows PAC is a
// few kilobytes, so a megabyte is generous while still refusing to allocate
// whatever a hostile endpoint asks for.
const maxKDCResponse = 1 << 20

// TargetDomainKey is the Target.Extra key the scanner uses to pass --domain
// through to modules that need a realm.
const TargetDomainKey = "domain"

// etypeID2Default is the encryption type to pre-authenticate with when the KDC
// does not say which one it wants. Every supported Active Directory version
// accepts aes256-cts-hmac-sha1-96.
const etypeID2Default = etypeID.AES256_CTS_HMAC_SHA1_96

// kdcExchange sends one Kerberos message to the KDC and returns the reply.
// Kerberos over TCP (RFC 4120 7.2.2) prefixes every message with its length as
// a 4-byte big-endian integer.
func kdcExchange(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, request []byte) ([]byte, error) {
	conn, err := dialer.DialContext(ctx, "tcp", target.Addr())
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	framed := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(request))) //nolint:gosec // an AS-REQ is always far below 4 GiB
	copy(framed[4:], request)

	if _, err = conn.Write(framed); err != nil {
		return nil, err
	}

	var header [4]byte
	if _, err = utils.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}

	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxKDCResponse {
		return nil, fmt.Errorf("kdc announced a %d byte reply, which is not a Kerberos message", size)
	}

	response := make([]byte, size)
	if _, err = utils.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}

// krbConfig builds an in-memory krb5 configuration pointing at the target.
//
// bruter deliberately never reads /etc/krb5.conf: the KDC is whichever target
// the operator passed, and silently inheriting the testing machine's own realm
// settings mid-engagement would be surprising. UDP is disabled because the
// dialer only speaks TCP (and so can honour --proxy).
func krbConfig(realm, kdc string) (*config.Config, error) {
	const enctypes = "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac"

	conf := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_kdc = false
 dns_lookup_realm = false
 udp_preference_limit = 1
 permitted_enctypes = %s
 default_tkt_enctypes = %s
 default_tgs_enctypes = %s

[realms]
 %s = {
  kdc = %s
 }
`, realm, enctypes, enctypes, enctypes, realm, kdc)

	return config.NewFromString(conf)
}

// validRealm reports whether a realm name is safe to place in a generated
// krb5.conf. The realm arrives from --domain or a wordlist, so a value
// carrying newlines or braces could otherwise inject configuration directives.
func validRealm(realm string) bool {
	if realm == "" || len(realm) > 255 {
		return false
	}
	for _, r := range realm {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// splitPrincipal pulls the realm out of a username written as user@REALM or
// REALM\user, falling back to the realm the scanner attached to the target
// from --domain. Realms are upper-cased: AD KDCs are case-sensitive here.
func splitPrincipal(username string, target *Target) (user, realm string, err error) {
	switch {
	case strings.Contains(username, "@"):
		i := strings.LastIndex(username, "@")
		user, realm = username[:i], username[i+1:]
	case strings.Contains(username, `\`):
		realm, user, _ = strings.Cut(username, `\`)
	default:
		user = username
		realm, _ = target.GetExtra(TargetDomainKey)
	}

	user = strings.TrimSpace(user)
	realm = strings.ToUpper(strings.TrimSpace(realm))

	if user == "" {
		return "", "", errors.New("kerberos: empty username")
	}
	if realm == "" {
		return "", "", errors.New("kerberos: no realm given; pass --domain or write usernames as user@REALM")
	}
	if !validRealm(realm) {
		return "", "", fmt.Errorf("kerberos: %q is not a usable realm name", realm)
	}
	return user, realm, nil
}

// asResult is the KDC's answer to one AS-REQ.
type asResult struct {
	// Granted reports that the KDC issued an AS-REP instead of an error.
	Granted bool
	Rep     messages.ASRep
	Err     *messages.KRBError
}

// asExchange sends one AS-REQ for a TGT and classifies the answer. Passing a
// nil preauth sends the request without pre-authentication, which is what
// makes the KDC disclose both the account's existence and the encryption type
// and salt to use next.
func asExchange(
	ctx context.Context,
	dialer *utils.ProxyAwareDialer,
	timeout time.Duration,
	target *Target,
	cfg *config.Config,
	realm, user string,
	preauth *types.PAData,
) (asResult, error) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)

	request, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return asResult{}, fmt.Errorf("build AS-REQ: %w", err)
	}
	if preauth != nil {
		request.PAData = append(request.PAData, *preauth)
	}

	raw, err := request.Marshal()
	if err != nil {
		return asResult{}, fmt.Errorf("marshal AS-REQ: %w", err)
	}

	response, err := kdcExchange(ctx, dialer, timeout, target, raw)
	if err != nil {
		return asResult{}, err
	}

	var rep messages.ASRep
	if rep.Unmarshal(response) == nil {
		return asResult{Granted: true, Rep: rep}, nil
	}

	var krbErr messages.KRBError
	if err = krbErr.Unmarshal(response); err != nil {
		return asResult{}, fmt.Errorf("kdc reply is neither AS-REP nor KRB-ERROR: %w", err)
	}
	return asResult{Err: &krbErr}, nil
}

// preAuthETypeID picks the encryption type to pre-authenticate with.
// RFC 4120 5.2.7.5 gives ETYPE-INFO2 precedence over ETYPE-INFO.
func preAuthETypeID(pas types.PADataSequence) (int32, error) {
	var fallback int32

	for _, pa := range pas {
		switch pa.PADataType {
		case patype.PA_ETYPE_INFO2:
			info, err := pa.GetETypeInfo2()
			if err != nil {
				return 0, fmt.Errorf("read ETYPE-INFO2: %w", err)
			}
			if len(info) > 0 {
				return info[0].EType, nil
			}
		case patype.PA_ETYPE_INFO:
			info, err := pa.GetETypeInfo()
			if err != nil {
				return 0, fmt.Errorf("read ETYPE-INFO: %w", err)
			}
			if len(info) > 0 {
				fallback = info[0].EType
			}
		}
	}

	if fallback != 0 {
		return fallback, nil
	}
	return 0, errors.New("kdc advertised no encryption type for pre-authentication")
}

// buildPAEncTimestamp derives the account's long-term key from the candidate
// password, using the encryption type and salt the KDC advertised in its
// PREAUTH_REQUIRED error, and encrypts the current time with it. A KDC that
// can decrypt the result has confirmed the password.
func buildPAEncTimestamp(password, user, realm string, krbErr *messages.KRBError) (*types.PAData, error) {
	var pas types.PADataSequence
	if len(krbErr.EData) > 0 {
		if err := pas.Unmarshal(krbErr.EData); err != nil {
			// Not every KDC puts usable data here. Falling back to the
			// defaults is better than abandoning the account, and a wrong
			// guess comes back as ETYPE_NOSUPP rather than a false negative.
			logger.Debugf("kerberos: unreadable pre-auth data from %s (%v), using default encryption type and salt",
				krbErr.Realm, err)
			pas = nil
		}
	}

	etypeID, err := preAuthETypeID(pas)
	if err != nil {
		logger.Debugf("kerberos: %v, using aes256-cts-hmac-sha1-96", err)
		etypeID = etypeID2Default
	}

	// Prefer the principal the KDC echoed back: the salt is built from it, and
	// a KDC may canonicalize the name we sent.
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, user)
	if len(krbErr.CName.NameString) > 0 {
		cname = krbErr.CName
	}
	saltRealm := realm
	if krbErr.CRealm != "" {
		saltRealm = krbErr.CRealm
	}

	key, _, err := crypto.GetKeyFromPassword(password, cname, saltRealm, etypeID, pas)
	if err != nil {
		return nil, fmt.Errorf("derive key from password: %w", err)
	}

	timestamp, err := types.GetPAEncTSEncAsnMarshalled()
	if err != nil {
		return nil, fmt.Errorf("build pre-auth timestamp: %w", err)
	}

	encrypted, err := crypto.GetEncryptedData(timestamp, key, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return nil, fmt.Errorf("encrypt pre-auth timestamp: %w", err)
	}

	value, err := encrypted.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal pre-auth timestamp: %w", err)
	}

	return &types.PAData{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: value}, nil
}

// verifyASRepPassword checks a candidate password against an AS-REP the KDC
// issued without pre-authentication. The reply's encrypted part is sealed with
// the account's long-term key, so decrypting it proves the password.
func verifyASRepPassword(rep messages.ASRep, user, realm, password string) bool {
	creds := credentials.New(user, realm).WithPassword(password)
	_, err := rep.DecryptEncPart(creds)
	return err == nil
}

// krbErrorf turns an unexpected KRB-ERROR into a Go error. Codes the modules
// understand are handled before this is reached, so anything arriving here is
// a genuine protocol or configuration problem and should count as a failure
// against --max-retries.
func krbErrorf(e *messages.KRBError) error {
	text := strings.TrimSpace(e.EText)
	if text == "" {
		return fmt.Errorf("kdc returned %s (%d)", errorcode.Lookup(e.ErrorCode), e.ErrorCode)
	}
	return fmt.Errorf("kdc returned %s (%d): %s", errorcode.Lookup(e.ErrorCode), e.ErrorCode, text)
}

// KerberosHandler is an implementation of ModuleHandler for Kerberos
// pre-authentication. An AS-REQ carrying PA-ENC-TIMESTAMP is the channel
// Active Directory password sprays normally run over: it needs no SMB or LDAP
// session, and the KDC's error codes distinguish a wrong password from a
// locked account.
//
// Every attempt here increments the account's lockout counter on the domain
// controller, exactly as a logon would. Use --spray with
// --max-attempts-per-user against live directories.
func KerberosHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	user, realm, err := splitPrincipal(credential.Username, target)
	if err != nil {
		return false, err
	}

	cfg, err := krbConfig(realm, target.Addr())
	if err != nil {
		return false, fmt.Errorf("kerberos config: %w", err)
	}

	// First exchange carries no pre-auth. The KDC answers with the encryption
	// type and salt to use, and says whether the account exists at all.
	probe, err := asExchange(ctx, dialer, timeout, target, cfg, realm, user, nil)
	if err != nil {
		return false, err
	}

	if probe.Granted {
		// The account has "do not require Kerberos pre-authentication" set, so
		// the KDC hands a TGT to anyone who asks for one. The password can
		// only be checked by decrypting that reply.
		return verifyASRepPassword(probe.Rep, user, realm, credential.Password), nil
	}

	switch probe.Err.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		// Expected: fall through to the pre-authenticated exchange.
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return false, nil
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		logger.Failf("%s: account %s@%s is locked out or disabled, no password was submitted", target.Addr(), user, realm)
		return false, nil
	case errorcode.KRB_AP_ERR_SKEW:
		// By far the most common Kerberos failure, and it looks exactly like a
		// dead host once --max-retries gives up on it.
		logger.Failf("%s: clock skew between this host and the KDC is too large for Kerberos; sync the clock", target.Addr())
		return false, krbErrorf(probe.Err)
	case errorcode.KDC_ERR_WRONG_REALM:
		logger.Failf("%s: the KDC does not serve realm %s; check --domain", target.Addr(), realm)
		return false, krbErrorf(probe.Err)
	default:
		return false, krbErrorf(probe.Err)
	}

	preauth, err := buildPAEncTimestamp(credential.Password, user, realm, probe.Err)
	if err != nil {
		return false, err
	}

	attempt, err := asExchange(ctx, dialer, timeout, target, cfg, realm, user, preauth)
	if err != nil {
		return false, err
	}
	if attempt.Granted {
		return true, nil
	}

	switch attempt.Err.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_FAILED:
		return false, nil
	case errorcode.KDC_ERR_KEY_EXPIRED:
		// The password was accepted; the KDC is only refusing because it has
		// expired. That is still a valid credential.
		logger.Successf("%s: %s@%s password is correct but expired", target.Addr(), user, realm)
		return true, nil
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		logger.Failf("%s: account %s@%s is now locked out or disabled", target.Addr(), user, realm)
		return false, nil
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return false, nil
	default:
		return false, krbErrorf(attempt.Err)
	}
}

// KerberosEnumHandler is an implementation of ModuleHandler for Kerberos user
// enumeration. The password field is ignored: an AS-REQ without
// pre-authentication makes the KDC disclose whether a principal exists without
// ever submitting a password, so this costs no lockout budget and is normally
// the first thing run against a new domain.
//
// Accounts that answer with a TGT have pre-authentication disabled, which
// makes them AS-REP roastable.
func KerberosEnumHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	user, realm, err := splitPrincipal(credential.Username, target)
	if err != nil {
		return false, err
	}

	cfg, err := krbConfig(realm, target.Addr())
	if err != nil {
		return false, fmt.Errorf("kerberos config: %w", err)
	}

	result, err := asExchange(ctx, dialer, timeout, target, cfg, realm, user, nil)
	if err != nil {
		return false, err
	}

	if result.Granted {
		logger.Successf("%s: %s@%s does not require Kerberos pre-authentication (AS-REP roastable)",
			target.Addr(), user, realm)
		return true, nil
	}

	switch result.Err.ErrorCode {
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return true, nil
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		logger.Successf("%s: %s@%s exists but is locked out or disabled", target.Addr(), user, realm)
		return true, nil
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return false, nil
	case errorcode.KRB_AP_ERR_SKEW:
		logger.Failf("%s: clock skew between this host and the KDC is too large for Kerberos; sync the clock", target.Addr())
		return false, krbErrorf(result.Err)
	case errorcode.KDC_ERR_WRONG_REALM:
		logger.Failf("%s: the KDC does not serve realm %s; check --domain", target.Addr(), realm)
		return false, krbErrorf(result.Err)
	default:
		return false, krbErrorf(result.Err)
	}
}
