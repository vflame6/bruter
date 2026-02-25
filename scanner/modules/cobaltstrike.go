package modules

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vflame6/bruter/utils"
)

// CobaltStrikeHandler is an implementation of ModuleHandler for Cobalt Strike team server
// authentication (port 50050). Protocol sourced from thc-hydra hydra-cobaltstrike.c.
//
// Packet layout (261 bytes):
//
//	[0..3]   = 0x00 0x00 0xBE 0xEF  (magic header)
//	[4]      = len(password) as uint8
//	[5..260] = password bytes, zero-padded to 256 bytes
//
// Server responds with 4 bytes: [0x00, 0x00, 0xCA, 0xFE] = success, anything else = fail.
//
// credential.Username is unused — CS uses only a shared team password.
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

	// Build 261-byte packet.
	pass := []byte(credential.Password)
	if len(pass) > 256 {
		pass = pass[:256]
	}

	var buf [261]byte
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0xBE
	buf[3] = 0xEF
	buf[4] = byte(len(pass)) //nolint:gosec // max 256, fits in uint8
	copy(buf[5:], pass)
	// Remaining bytes (buf[5+len(pass):]) are already zero from var declaration.

	if _, err = conn.Write(buf[:]); err != nil {
		return false, err
	}

	// Read 4-byte server response.
	var resp [4]byte
	if _, err = io.ReadFull(conn, resp[:]); err != nil {
		return false, nil //nolint:nilerr // closed/short read = wrong password
	}

	// [0x00, 0x00, 0xCA, 0xFE] = success
	if resp[0] == 0x00 && resp[1] == 0x00 && resp[2] == 0xCA && resp[3] == 0xFE {
		return true, nil
	}
	return false, nil
}
