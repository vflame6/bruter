package modules

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// CobaltStrikeHandler is an implementation of ModuleHandler for Cobalt Strike team server
// authentication (port 50050). Connects via TLS and sends SHA-256(password) prefixed with
// a 4-byte big-endian length. If the server closes the connection, the password is wrong;
// if data is returned, authentication succeeded.
//
// credential.Username is unused — CS uses only a shared password/secret.
func CobaltStrikeHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))

	tlsCfg := utils.GetTLSConfig()
	tlsCfg.ServerName = "" // CS uses self-signed cert; hostname verification skipped

	conn, err := dialer.DialTLSContext(ctx, "tcp", addr, tlsCfg)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Payload: 4-byte big-endian length (32) + 32-byte SHA-256 hash of the password.
	hash := sha256.Sum256([]byte(credential.Password))
	var buf [36]byte
	binary.BigEndian.PutUint32(buf[:4], 32)
	copy(buf[4:], hash[:])

	if _, err = conn.Write(buf[:]); err != nil {
		return false, err
	}

	// If server closes before sending 4 bytes → wrong password (or not a CS team server).
	var resp [4]byte
	if _, err = io.ReadFull(conn, resp[:]); err != nil {
		return false, nil //nolint:nilerr // closed connection = auth failure, not an error
	}
	return true, nil
}
