package modules

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/linxGnu/gosmpp"
	"github.com/linxGnu/gosmpp/data"
	"github.com/linxGnu/gosmpp/pdu"
	"github.com/vflame6/bruter/utils"
	"net"
	"strconv"
	"strings"
	"time"
)

// SMPPErrAuth represents an authentication error (invalid credentials).
var SMPPErrAuth = errors.New("authentication error")

// SMPPHandler is an implementation of ModuleHandler for SMPP service
func SMPPHandler(ctx context.Context, d *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	// Create authentication config
	auth := gosmpp.Auth{
		SMSC:       addr,
		SystemID:   credential.Username,
		Password:   credential.Password,
		SystemType: "",
	}

	// Create dialer based on secure flag
	var dialer gosmpp.Dialer
	if target.Encryption {
		dialer = createTLSSMPPDialer(ctx, d)
	} else {
		dialer = createNonTLSSMPPDialer(ctx, d)
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
		errType := classifySMPPError(err)
		// check for authentication error
		if errors.Is(errType, SMPPErrAuth) {
			return false, nil
		}
		// connection error
		return false, err
	}

	// successful connection and authentication
	_ = session.Close()
	return true, nil
}

// createTLSSMPPDialer creates a TLS dialer with InsecureSkipVerify enabled.
func createTLSSMPPDialer(ctx context.Context, d *utils.ProxyAwareDialer) gosmpp.Dialer {
	return func(addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}

		tlsConfig := utils.GetTLSConfig()

		tlsConn := tls.Client(conn, tlsConfig)

		if err := tlsConn.SetDeadline(time.Now().Add(d.Timeout())); err != nil {
			_ = conn.Close()
			return nil, err
		}

		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, err
		}

		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// createNonTLSSMPPDialer creates a plain TCP dialer with timeout.
func createNonTLSSMPPDialer(ctx context.Context, d *utils.ProxyAwareDialer) gosmpp.Dialer {
	return func(addr string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", addr)
	}
}

// classifySMPPError categorizes the error into TLS, Auth, or Connection error.
func classifySMPPError(err error) error {
	if err == nil {
		return nil
	}

	// Check for authentication errors (SMPP bind errors)
	if isSMPPAuthError(err) {
		return fmt.Errorf("%w: %v", SMPPErrAuth, err)
	}

	// Default to connection error
	return err
}

// isSMPPAuthError checks if the error is authentication-related.
func isSMPPAuthError(err error) bool {
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
	if utils.ContainsAny(errStr,
		"invalid password",
		"invalid system",
		"authentication",
		"bind failed",
		"access denied",
		"unauthorized",
		"command status: [13]", // ESME_RBINDFAIL
		"command status: [14]", // ESME_RINVPASWD
		"command status: [15]", // ESME_RINVSYSID
	) {
		return true
	}

	return false
}
