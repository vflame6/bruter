package modules

import (
	"context"
	"time"

	"github.com/vflame6/bruter/utils"
)

// S7Handler is an implementation of ModuleHandler for Siemens S7 PLC (port 102).
// Implements the S7comm password authentication protocol.
// Password-only auth (username is ignored) — S7 PLCs use a single CPU protection password.
// Protocol flow: COTP connect → S7 negotiate PDU → S7 password request.
func S7Handler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: COTP Connection Request.
	cotpConnect := []byte{
		0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x17,
		0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0,
		0x01, 0x0a,
	}
	if _, err = conn.Write(cotpConnect); err != nil {
		return false, err
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return false, err
	}
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return false, nil
	}

	// Step 2: S7 Negotiate PDU.
	s7Negotiate := []byte{
		0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, 0x01, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0xf0, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x01, 0xe0,
	}
	if _, err = conn.Write(s7Negotiate); err != nil {
		return false, err
	}
	n, err = conn.Read(buf)
	if err != nil || n < 2 {
		return false, err
	}
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return false, nil
	}

	// Step 3: Prepare and send password.
	// S7 passwords are exactly 8 bytes, space-padded, XOR-encoded.
	const s7PassLen = 8
	pass := make([]byte, s7PassLen)
	copy(pass, credential.Password)
	// Pad with spaces if shorter.
	for i := len(credential.Password); i < s7PassLen; i++ {
		pass[i] = ' '
	}

	// XOR encode: first two bytes XOR 0x55, rest XOR (prev_encoded[i-2] ^ 0x55).
	encoded := make([]byte, s7PassLen)
	encoded[0] = pass[0] ^ 0x55
	encoded[1] = pass[1] ^ 0x55
	for i := 2; i < s7PassLen; i++ {
		encoded[i] = pass[i] ^ encoded[i-2] ^ 0x55
	}

	// S7 password request header (29 bytes) + 8 bytes encoded password.
	s7PasswordReq := []byte{
		0x03, 0x00, 0x00, 0x25, 0x02, 0xf0, 0x80, 0x32, 0x07, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x01, 0x12,
		0x04, 0x11, 0x45, 0x01, 0x00, 0xff, 0x09, 0x00, 0x08,
	}
	packet := make([]byte, 0, len(s7PasswordReq)+s7PassLen)
	packet = append(packet, s7PasswordReq...)
	packet = append(packet, encoded...)

	if _, err = conn.Write(packet); err != nil {
		return false, err
	}

	n, err = conn.Read(buf)
	if err != nil || n < 2 {
		return false, err
	}
	if buf[0] != 0x03 || buf[1] != 0x00 {
		return false, nil
	}

	// Check S7 response for success.
	// In a successful auth, the error class (byte at offset 17) should be 0x00.
	// Error class 0xd6 or non-zero = wrong password.
	if n > 17 && buf[17] == 0x00 {
		return true, nil
	}

	return false, nil
}
