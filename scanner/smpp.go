package scanner

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/linxGnu/gosmpp"
	"github.com/linxGnu/gosmpp/data"
	"github.com/linxGnu/gosmpp/pdu"
	"github.com/vflame6/bruter/logger"
	"net"
	"strings"
	"sync"
	"time"
)

// SMPPErrTLS represents a TLS-specific error (handshake failure, certificate issues).
var SMPPErrTLS = errors.New("TLS error")

// SMPPErrAuth represents an authentication error (invalid credentials).
var SMPPErrAuth = errors.New("authentication error")

// SMPPErrConnection represents a network/connection error.
var SMPPErrConnection = errors.New("connection error")

// ============================================================================
// SMPPChecker - Main checker function
// ============================================================================

// SMPPChecker checks SMPP server availability and credential validity.
//
// The checker first attempts a TLS connection. If TLS fails (not a network error),
// it falls back to a non-TLS connection.
//
// Parameters:
//   - target: IP address of the SMPP server
//   - port: Port number of the SMPP server
//   - username: SMPP SystemID for authentication
//   - password: SMPP password for authentication
//
// Returns:
//   - success (bool): true if credentials are valid, false if invalid
//   - tls (bool): true if TLS connection was used, false if plain TCP
//   - err (error): non-nil only for connection errors (not auth/TLS errors)
//
// Examples:
//   - (true, true, nil)   - Valid credentials over TLS
//   - (true, false, nil)  - Valid credentials over plain TCP (TLS failed)
//   - (false, true, nil)  - Invalid credentials, TLS worked
//   - (false, false, nil) - Invalid credentials, TLS failed, plain TCP used
//   - (false, false, err) - Connection error (server unreachable, etc.)
func SMPPChecker(target *Target, opts *Options) (bool, bool, error) {
	defaultUsername := "smppclient1"
	defaultPassword := "password"

	logger.Debugf("trying default credentials on %s:%d", target.IP, target.Port)

	// Step 1: Try TLS connection
	session, err := GetSMPPConnection(target.IP, target.Port, true, opts.Timeout, defaultUsername, defaultPassword)

	if err == nil {
		// TLS connection successful, credentials valid
		_ = session.Close()
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
		return true, true, nil
	}

	// Analyze the error
	if errors.Is(err, SMPPErrAuth) {
		// TLS worked, but authentication failed
		return false, true, nil
	}

	// Try non-TLS as fallback
	logger.Debugf("failed to connect to %s:%d with TLS, trying plaintext", target.IP, target.Port)
	session, err = GetSMPPConnection(target.IP, target.Port, false, opts.Timeout, defaultUsername, defaultPassword)

	if err == nil {
		// Non-TLS connection successful, credentials valid
		_ = session.Close()
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, defaultUsername, defaultPassword)
		return true, false, nil
	}

	// Analyze the error
	if errors.Is(err, SMPPErrAuth) {
		// Authentication failed
		return false, false, nil
	}

	// Connection error
	return false, false, fmt.Errorf("connection failed: %w", err)
}

// SMPPHandler is an implementation of CommandHandler for SMPP service
func SMPPHandler(wg *sync.WaitGroup, credentials <-chan *Credential, opts *Options, target *Target) {
	defer wg.Done()

	for {
		credential, ok := <-credentials
		if !ok {
			break
		}
		// shutdown all threads if --stop-on-success is used and password is found
		if opts.StopOnSuccess && target.Success {
			break
		}

		logger.Debugf("trying %s:%d with credential %s:%s", target.IP, target.Port, credential.Username, credential.Password)

		session, err := GetSMPPConnection(target.IP, target.Port, target.Encryption, opts.Timeout, credential.Username, credential.Password)
		if err != nil {
			if opts.Delay > 0 {
				time.Sleep(opts.Delay)
			}
			continue
		}

		_ = session.Close()
		RegisterSuccess(opts.OutputFile, &opts.FileMutex, opts.Command, target, credential.Username, credential.Password)

		if opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
	}
}

// ============================================================================
// GetSMPPConnection - Establishes SMPP session
// ============================================================================

// GetSMPPConnection establishes an SMPP session with the specified parameters.
//
// Parameters:
//   - target: IP address of the SMPP server
//   - port: Port number of the SMPP server
//   - secure: If true, use TLS connection (with InsecureSkipVerify: true)
//   - timeout: Connection timeout duration
//   - username: SMPP SystemID for authentication
//   - password: SMPP password for authentication
//
// Returns:
//   - *gosmpp.Session: Established session (caller must close it)
//   - error: Connection or authentication error
func GetSMPPConnection(target net.IP, port int, secure bool, timeout time.Duration, username, password string) (*gosmpp.Session, error) {
	addr := fmt.Sprintf("%s:%d", target.String(), port)

	// Create authentication config
	auth := gosmpp.Auth{
		SMSC:       addr,
		SystemID:   username,
		Password:   password,
		SystemType: "",
	}

	// Create dialer based on secure flag
	var dialer gosmpp.Dialer
	if secure {
		dialer = createTLSDialer(timeout)
	} else {
		dialer = createNonTLSDialer(timeout)
	}

	// Session settings - minimal for connection check
	settings := gosmpp.Settings{
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
		EnquireLink:  0, // Disable enquire link for checker

		// Minimal callbacks - we don't need to process PDUs for connection check
		OnPDU:            func(p pdu.PDU, responded bool) {},
		OnSubmitError:    func(p pdu.PDU, err error) {},
		OnReceivingError: func(err error) {},
		OnRebindingError: func(err error) {},
		OnClosed:         func(state gosmpp.State) {},
	}

	// Create session with Transceiver connector
	// Disable auto-rebind (rebindingInterval <= 0)
	session, err := gosmpp.NewSession(
		gosmpp.TRXConnector(dialer, auth),
		settings,
		0, // No auto-rebind
	)

	if err != nil {
		return nil, classifyError(err, secure)
	}

	return session, nil
}

// createTLSDialer creates a TLS dialer with InsecureSkipVerify enabled.
func createTLSDialer(timeout time.Duration) gosmpp.Dialer {
	return func(addr string) (net.Conn, error) {
		// Extract host for TLS config
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Establish TCP connection with timeout
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return nil, err
		}

		// Create TLS config with InsecureSkipVerify
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
		}

		// Upgrade to TLS
		tlsConn := tls.Client(conn, tlsConfig)

		// Set handshake deadline
		if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}

		// Perform TLS handshake
		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("%w: %v", SMPPErrTLS, err)
		}

		// Reset deadline
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// createNonTLSDialer creates a plain TCP dialer with timeout.
func createNonTLSDialer(timeout time.Duration) gosmpp.Dialer {
	return func(addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", addr, timeout)
	}
}

// classifyError categorizes the error into TLS, Auth, or Connection error.
func classifyError(err error, wasTLS bool) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for TLS errors
	if wasTLS && isTLSError(err) {
		return fmt.Errorf("%w: %v", SMPPErrTLS, err)
	}

	// Check for authentication errors (SMPP bind errors)
	if isAuthError(err) {
		return fmt.Errorf("%w: %v", SMPPErrAuth, err)
	}

	// Check error message for TLS indicators
	if wasTLS && containsTLSErrorIndicator(errStr) {
		return fmt.Errorf("%w: %v", SMPPErrTLS, err)
	}

	// Default to connection error
	return fmt.Errorf("%w: %v", SMPPErrConnection, err)
}

// isTLSError checks if the error is TLS-related.
func isTLSError(err error) bool {
	// Check if error already wrapped as TLS error
	if errors.Is(err, SMPPErrTLS) {
		return true
	}

	// Check for TLS record/alert errors
	var tlsRecordErr tls.RecordHeaderError
	if errors.As(err, &tlsRecordErr) {
		return true
	}

	return false
}

// containsTLSErrorIndicator checks error message for TLS-related keywords.
func containsTLSErrorIndicator(errStr string) bool {
	tlsIndicators := []string{
		"tls:",
		"TLS",
		"certificate",
		"handshake",
		"x509",
		"ssl",
		"SSL",
		"first record does not look like a TLS handshake",
		"oversized record",
		"alert",
	}

	errLower := strings.ToLower(errStr)
	for _, indicator := range tlsIndicators {
		if strings.Contains(errLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// isAuthError checks if the error is authentication-related.
func isAuthError(err error) bool {
	// Check for gosmpp.BindError
	var bindErr gosmpp.BindError
	if errors.As(err, &bindErr) {
		switch bindErr.CommandStatus {
		case data.ESME_RINVPASWD: // Invalid Password
			return true
		case data.ESME_RINVSYSID: // Invalid System ID
			return true
		case data.ESME_RBINDFAIL: // Bind Failed (often auth-related)
			return true
		case data.ESME_RINVBNDSTS: // Incorrect BIND Status
			return true
		}
	}

	// Check error message for auth indicators
	errStr := strings.ToLower(err.Error())
	authIndicators := []string{
		"invalid password",
		"invalid system",
		"authentication",
		"bind failed",
		"access denied",
		"unauthorized",
		"command status: [13]", // ESME_RBINDFAIL
		"command status: [14]", // ESME_RINVPASWD
		"command status: [15]", // ESME_RINVSYSID
	}

	for _, indicator := range authIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}

	return false
}
