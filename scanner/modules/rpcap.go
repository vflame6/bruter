package modules

import (
	"context"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RPCAPHandler is an implementation of ModuleHandler for RPCAP (Remote Packet Capture).
// Implements the RPCAP authentication protocol (port 2002).
// Protocol: send auth request packet with username/password, check response opcode.
func RPCAPHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	user := []byte(credential.Username)
	pass := []byte(credential.Password)

	// RPCAP auth request packet:
	// Byte 0:   version (0x00)
	// Byte 1:   opcode (0x08 = auth request)
	// Bytes 2-5: reserved (0x00000000) + payload length
	// Bytes 6-7: unused
	// Payload:  auth_type(2) + padding(2) + username_len(2) + padding(1) + password_len(1) + username + password
	payloadLen := 8 + len(user) + len(pass)
	packet := make([]byte, 8+payloadLen)

	packet[0] = 0x00 // version
	packet[1] = 0x08 // opcode: auth request
	// Bytes 2-3: unused
	// Bytes 4-7: payload length (big-endian uint32)
	packet[4] = byte(payloadLen >> 24)
	packet[5] = byte(payloadLen >> 16)
	packet[6] = byte(payloadLen >> 8)
	packet[7] = byte(payloadLen)

	// Auth payload:
	// Bytes 0-1: auth type (0x0001 = password auth)
	packet[8] = 0x00
	packet[9] = 0x01
	// Bytes 2-3: padding
	// Bytes 4-5: reserved
	// Byte 6: username length
	packet[13] = byte(len(user))
	// Byte 7: padding
	// Byte 8: password length
	packet[15] = byte(len(pass))

	// Username + password
	copy(packet[16:], user)
	copy(packet[16+len(user):], pass)

	if _, err = conn.Write(packet); err != nil {
		return false, err
	}

	// Read response header (8 bytes minimum).
	resp := make([]byte, 8)
	n, err := conn.Read(resp)
	if err != nil || n < 2 {
		return false, err
	}

	// Response opcode 0x88 = auth success (0x80 | 0x08).
	// Response opcode with error flag = auth failure.
	if resp[1] == 0x88 {
		return true, nil
	}
	return false, nil
}
