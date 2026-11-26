package modules

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/vflame6/bruter/utils"
)

// --- realm handling ---

func TestValidRealmRejectsConfigInjection(t *testing.T) {
	// The realm is interpolated into a generated krb5.conf, so a value
	// carrying a newline could append directives of its own.
	bad := []string{
		"",
		"CORP.LOCAL\n kdc = attacker.example",
		"CORP LOCAL",
		"CORP.LOCAL}",
		"CORP.LOCAL\r\n[realms]",
		"CORP=LOCAL",
		"CORP/LOCAL",
		strings.Repeat("A", 256),
	}
	for _, realm := range bad {
		if validRealm(realm) {
			t.Errorf("validRealm(%q) = true, want false", realm)
		}
	}

	good := []string{"CORP.LOCAL", "corp-ad.example.com", "AD_1.TEST", "EXAMPLE"}
	for _, realm := range good {
		if !validRealm(realm) {
			t.Errorf("validRealm(%q) = false, want true", realm)
		}
	}
}

func TestSplitPrincipal(t *testing.T) {
	withDomain := &Target{IP: net.ParseIP("10.0.0.1"), Port: 88}
	withDomain.SetExtra(TargetDomainKey, "corp.local")

	bare := &Target{IP: net.ParseIP("10.0.0.1"), Port: 88}

	cases := []struct {
		name      string
		username  string
		target    *Target
		wantUser  string
		wantRealm string
		wantErr   bool
	}{
		{name: "user@realm", username: "alice@corp.local", target: bare, wantUser: "alice", wantRealm: "CORP.LOCAL"},
		{name: "realm backslash user", username: `CORP.LOCAL\alice`, target: bare, wantUser: "alice", wantRealm: "CORP.LOCAL"},
		{name: "bare name uses --domain", username: "alice", target: withDomain, wantUser: "alice", wantRealm: "CORP.LOCAL"},
		{name: "username realm wins over --domain", username: "alice@other.example", target: withDomain, wantUser: "alice", wantRealm: "OTHER.EXAMPLE"},
		{name: "realm is upper-cased", username: "alice@corp.local", target: bare, wantUser: "alice", wantRealm: "CORP.LOCAL"},
		{name: "bare name without --domain fails", username: "alice", target: bare, wantErr: true},
		{name: "empty username fails", username: "@corp.local", target: bare, wantErr: true},
		{name: "unsafe realm fails", username: "alice@corp local", target: bare, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, realm, err := splitPrincipal(tc.username, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("splitPrincipal(%q) = (%q, %q, nil), want an error", tc.username, user, realm)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitPrincipal(%q): %v", tc.username, err)
			}
			if user != tc.wantUser || realm != tc.wantRealm {
				t.Errorf("splitPrincipal(%q) = (%q, %q), want (%q, %q)",
					tc.username, user, realm, tc.wantUser, tc.wantRealm)
			}
		})
	}
}

func TestSplitPrincipalKeepsUPNSuffix(t *testing.T) {
	// A UPN can contain more than one @; the realm is what follows the last.
	bare := &Target{IP: net.ParseIP("10.0.0.1"), Port: 88}
	user, realm, err := splitPrincipal("first.last@sub@corp.local", bare)
	if err != nil {
		t.Fatalf("splitPrincipal: %v", err)
	}
	if user != "first.last@sub" || realm != "CORP.LOCAL" {
		t.Errorf("got (%q, %q), want (%q, %q)", user, realm, "first.last@sub", "CORP.LOCAL")
	}
}

func TestKrbConfigPointsAtTheTarget(t *testing.T) {
	cfg, err := krbConfig("CORP.LOCAL", "10.0.0.1:88")
	if err != nil {
		t.Fatalf("krbConfig: %v", err)
	}
	if cfg.LibDefaults.DefaultRealm != "CORP.LOCAL" {
		t.Errorf("default_realm = %q, want CORP.LOCAL", cfg.LibDefaults.DefaultRealm)
	}
	if cfg.LibDefaults.DNSLookupKDC {
		t.Error("dns_lookup_kdc is enabled; the KDC must be the target the operator passed")
	}
	if len(cfg.Realms) != 1 || cfg.Realms[0].Realm != "CORP.LOCAL" {
		t.Fatalf("realms = %+v, want one entry for CORP.LOCAL", cfg.Realms)
	}
	if len(cfg.Realms[0].KDC) == 0 || !strings.Contains(cfg.Realms[0].KDC[0], "10.0.0.1") {
		t.Errorf("kdc = %v, want the target address", cfg.Realms[0].KDC)
	}
}

// --- pre-auth etype selection ---

func TestPreAuthETypeIDPrefersETypeInfo2(t *testing.T) {
	info2, err := marshalETypeInfo2(18, "CORP.LOCALalice")
	if err != nil {
		t.Fatal(err)
	}
	info1, err := marshalETypeInfo(23)
	if err != nil {
		t.Fatal(err)
	}

	// ETYPE-INFO is listed first on purpose: RFC 4120 5.2.7.5 still gives
	// ETYPE-INFO2 precedence.
	pas := types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO, PADataValue: info1},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2},
	}

	got, err := preAuthETypeID(pas)
	if err != nil {
		t.Fatalf("preAuthETypeID: %v", err)
	}
	if got != 18 {
		t.Errorf("etype = %d, want 18 from ETYPE-INFO2", got)
	}
}

func TestPreAuthETypeIDFallsBackToETypeInfo(t *testing.T) {
	info1, err := marshalETypeInfo(23)
	if err != nil {
		t.Fatal(err)
	}
	pas := types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO, PADataValue: info1}}

	got, err := preAuthETypeID(pas)
	if err != nil {
		t.Fatalf("preAuthETypeID: %v", err)
	}
	if got != 23 {
		t.Errorf("etype = %d, want 23", got)
	}
}

func TestPreAuthETypeIDErrorsWithoutETypeInfo(t *testing.T) {
	pas := types.PADataSequence{{PADataType: patype.PA_PW_SALT, PADataValue: []byte("salt")}}
	if _, err := preAuthETypeID(pas); err == nil {
		t.Fatal("expected an error when the KDC advertises no encryption type")
	}
}

// --- KDC exchange over the wire ---

// fakeKDC serves one framed reply per connection and records the requests it
// received.
type fakeKDC struct {
	listener net.Listener
	replies  [][]byte
	requests chan []byte
	done     chan struct{}
}

func startFakeKDC(t *testing.T, replies ...[]byte) *fakeKDC {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	k := &fakeKDC{
		listener: listener,
		replies:  replies,
		requests: make(chan []byte, 16),
		done:     make(chan struct{}),
	}

	go func() {
		defer close(k.done)
		var n int
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

				var header [4]byte
				if _, err := utils.ReadFull(conn, header[:]); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint32(header[:]))
				if _, err := utils.ReadFull(conn, body); err != nil {
					return
				}
				select {
				case k.requests <- body:
				default:
				}

				if n >= len(k.replies) {
					return
				}
				reply := k.replies[n]
				n++

				framed := make([]byte, 4+len(reply))
				binary.BigEndian.PutUint32(framed[:4], uint32(len(reply)))
				copy(framed[4:], reply)
				_, _ = conn.Write(framed)
			}()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		<-k.done
	})
	return k
}

func (k *fakeKDC) target(t *testing.T) *Target {
	t.Helper()
	host, port, err := net.SplitHostPort(k.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var portNum int
	if _, err := parsePort(port, &portNum); err != nil {
		t.Fatal(err)
	}
	target := &Target{IP: net.ParseIP(host), Port: portNum, OriginalTarget: k.listener.Addr().String()}
	target.SetExtra(TargetDomainKey, "corp.local")
	return target
}

func testDialer(t *testing.T) *utils.ProxyAwareDialer {
	t.Helper()
	dialer, err := utils.NewProxyAwareDialer("", "", 5*time.Second, "bruter-test", nil)
	if err != nil {
		t.Fatalf("NewProxyAwareDialer: %v", err)
	}
	return dialer
}

func krbErrorBytes(t *testing.T, code int32) []byte {
	t.Helper()
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/CORP.LOCAL")
	e := messages.NewKRBError(sname, "CORP.LOCAL", code, errorcode.Lookup(code))
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal KRBError: %v", err)
	}
	return b
}

func TestKerberosEnumClassifiesKDCAnswers(t *testing.T) {
	cases := []struct {
		name       string
		code       int32
		wantExists bool
	}{
		{name: "preauth required means the account exists", code: errorcode.KDC_ERR_PREAUTH_REQUIRED, wantExists: true},
		{name: "revoked means the account exists", code: errorcode.KDC_ERR_CLIENT_REVOKED, wantExists: true},
		{name: "unknown principal means no account", code: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, wantExists: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kdc := startFakeKDC(t, krbErrorBytes(t, tc.code))
			target := kdc.target(t)

			got, err := KerberosEnumHandler(context.Background(), testDialer(t), 5*time.Second, target,
				&Credential{Username: "alice"})
			if err != nil {
				t.Fatalf("KerberosEnumHandler: %v", err)
			}
			if got != tc.wantExists {
				t.Errorf("exists = %v, want %v for %s", got, tc.wantExists, errorcode.Lookup(tc.code))
			}
		})
	}
}

func TestKerberosEnumSubmitsNoPreAuthData(t *testing.T) {
	// The point of enumeration is that it costs no lockout budget, which only
	// holds if the AS-REQ carries no PA-ENC-TIMESTAMP.
	kdc := startFakeKDC(t, krbErrorBytes(t, errorcode.KDC_ERR_PREAUTH_REQUIRED))
	target := kdc.target(t)

	if _, err := KerberosEnumHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice", Password: "Autumn2026"}); err != nil {
		t.Fatalf("KerberosEnumHandler: %v", err)
	}

	raw := <-kdc.requests
	var req messages.ASReq
	if err := req.Unmarshal(raw); err != nil {
		t.Fatalf("the module did not send a parsable AS-REQ: %v", err)
	}
	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_ENC_TIMESTAMP {
			t.Fatal("enumeration sent PA-ENC-TIMESTAMP, which spends the account's lockout budget")
		}
	}
	if len(req.ReqBody.CName.NameString) == 0 || req.ReqBody.CName.NameString[0] != "alice" {
		t.Errorf("AS-REQ cname = %v, want alice", req.ReqBody.CName.NameString)
	}
	if req.ReqBody.Realm != "CORP.LOCAL" {
		t.Errorf("AS-REQ realm = %q, want CORP.LOCAL", req.ReqBody.Realm)
	}
}

func TestKerberosHandlerWrongPasswordIsNotAnError(t *testing.T) {
	// A rejected password must come back as (false, nil): returning an error
	// would spend the host's --max-retries budget on normal wrong guesses.
	info2, err := marshalETypeInfo2(etypeID.AES256_CTS_HMAC_SHA1_96, "CORP.LOCALalice")
	if err != nil {
		t.Fatal(err)
	}
	kdc := startFakeKDC(t,
		krbErrorWithPAData(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, types.PADataSequence{
			{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2},
		}),
		krbErrorBytes(t, errorcode.KDC_ERR_PREAUTH_FAILED),
	)
	target := kdc.target(t)

	ok, err := KerberosHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice", Password: "wrong"})
	if err != nil {
		t.Fatalf("KerberosHandler returned an error for a wrong password: %v", err)
	}
	if ok {
		t.Error("a rejected password was reported as valid")
	}
}

func TestKerberosHandlerUnknownUserIsNotAnError(t *testing.T) {
	kdc := startFakeKDC(t, krbErrorBytes(t, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN))
	target := kdc.target(t)

	ok, err := KerberosHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "nosuchuser", Password: "whatever"})
	if err != nil {
		t.Fatalf("KerberosHandler: %v", err)
	}
	if ok {
		t.Error("an unknown principal was reported as valid credentials")
	}
}

func TestKerberosHandlerLockedAccountIsNotAnError(t *testing.T) {
	kdc := startFakeKDC(t, krbErrorBytes(t, errorcode.KDC_ERR_CLIENT_REVOKED))
	target := kdc.target(t)

	ok, err := KerberosHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice", Password: "whatever"})
	if err != nil {
		t.Fatalf("KerberosHandler: %v", err)
	}
	if ok {
		t.Error("a locked account was reported as valid credentials")
	}
}

func TestKerberosHandlerSendsPreAuthOnSecondExchange(t *testing.T) {
	info2, err := marshalETypeInfo2(23, "")
	if err != nil {
		t.Fatal(err)
	}
	preauthRequired := krbErrorWithPAData(t, errorcode.KDC_ERR_PREAUTH_REQUIRED, types.PADataSequence{
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info2},
	})

	kdc := startFakeKDC(t, preauthRequired, krbErrorBytes(t, errorcode.KDC_ERR_PREAUTH_FAILED))
	target := kdc.target(t)

	if _, err := KerberosHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice", Password: "Autumn2026"}); err != nil {
		t.Fatalf("KerberosHandler: %v", err)
	}

	first := <-kdc.requests
	second := <-kdc.requests

	var req1, req2 messages.ASReq
	if err := req1.Unmarshal(first); err != nil {
		t.Fatalf("first AS-REQ unparsable: %v", err)
	}
	if err := req2.Unmarshal(second); err != nil {
		t.Fatalf("second AS-REQ unparsable: %v", err)
	}

	if hasPAEncTimestamp(req1.PAData) {
		t.Error("the first AS-REQ carried PA-ENC-TIMESTAMP before the KDC named an encryption type")
	}
	if !hasPAEncTimestamp(req2.PAData) {
		t.Error("the second AS-REQ carried no PA-ENC-TIMESTAMP, so no password was ever submitted")
	}
}

func TestKerberosHandlerUnexpectedErrorCodeIsAnError(t *testing.T) {
	// A misconfiguration should surface, not look like a wrong password.
	kdc := startFakeKDC(t, krbErrorBytes(t, errorcode.KDC_ERR_WRONG_REALM))
	target := kdc.target(t)

	if _, err := KerberosHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice", Password: "whatever"}); err == nil {
		t.Fatal("expected an error for an unexpected KDC error code")
	}
}

func TestKerberosRejectsOversizedReply(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		var header [4]byte
		if _, err := utils.ReadFull(conn, header[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(header[:]))
		if _, err := utils.ReadFull(conn, body); err != nil {
			return
		}
		// Claim a 2 GiB message without sending it.
		_, _ = conn.Write([]byte{0x80, 0x00, 0x00, 0x00})
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var portNum int
	if _, err := parsePort(port, &portNum); err != nil {
		t.Fatal(err)
	}
	target := &Target{IP: net.ParseIP(host), Port: portNum}
	target.SetExtra(TargetDomainKey, "corp.local")

	_, err = KerberosEnumHandler(context.Background(), testDialer(t), 5*time.Second, target,
		&Credential{Username: "alice"})
	if err == nil {
		t.Fatal("expected an error for an implausible reply length")
	}
	if !strings.Contains(err.Error(), "not a Kerberos message") {
		t.Errorf("error = %v, want it to name the implausible length", err)
	}
}

func TestKerberosHandlerRequiresRealm(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 88}

	_, err := KerberosHandler(context.Background(), testDialer(t), time.Second, target,
		&Credential{Username: "alice", Password: "p"})
	if err == nil {
		t.Fatal("expected an error when no realm is available")
	}
	if !strings.Contains(err.Error(), "realm") {
		t.Errorf("error = %v, want it to mention the missing realm", err)
	}
}

// --- test helpers ---

// parsePort turns a listener's port string into an int.
func parsePort(port string, out *int) (int, error) {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	*out = n
	return n, nil
}

// marshalETypeInfo2 builds the PA-DATA value a KDC sends to name the
// encryption type and salt to pre-authenticate with.
func marshalETypeInfo2(etype int32, salt string) ([]byte, error) {
	return asn1.Marshal(types.ETypeInfo2{{EType: etype, Salt: salt}})
}

// marshalETypeInfo builds the older ETYPE-INFO form.
func marshalETypeInfo(etype int32) ([]byte, error) {
	return asn1.Marshal(types.ETypeInfo{{EType: etype}})
}

// krbErrorWithPAData marshals a KRB-ERROR carrying pre-auth data in e-data,
// the way a real KDC answers KDC_ERR_PREAUTH_REQUIRED.
func krbErrorWithPAData(t *testing.T, code int32, pas types.PADataSequence) []byte {
	t.Helper()

	edata, err := asn1.Marshal(pas)
	if err != nil {
		t.Fatalf("marshal PAData sequence: %v", err)
	}

	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/CORP.LOCAL")
	e := messages.NewKRBError(sname, "CORP.LOCAL", code, errorcode.Lookup(code))
	e.EData = edata
	e.CRealm = "CORP.LOCAL"
	e.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal KRBError: %v", err)
	}
	return b
}

func hasPAEncTimestamp(pas types.PADataSequence) bool {
	for _, pa := range pas {
		if pa.PADataType == patype.PA_ENC_TIMESTAMP {
			return true
		}
	}
	return false
}
