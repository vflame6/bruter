package modules

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/vflame6/bruter/utils"
)

// MemcachedHandler is an implementation of ModuleHandler for Memcached SASL authentication.
// Implements the Memcached binary protocol SASL auth (PLAIN mechanism) directly.
// No external libmemcached dependency required.
func MemcachedHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Build SASL PLAIN auth value: \x00username\x00password
	authValue := make([]byte, 0, 1+len(credential.Username)+1+len(credential.Password))
	authValue = append(authValue, 0)
	authValue = append(authValue, []byte(credential.Username)...)
	authValue = append(authValue, 0)
	authValue = append(authValue, []byte(credential.Password)...)

	mechanism := "PLAIN"

	// Memcached binary protocol header (24 bytes) + extras.
	// Opcode 0x21 = SASL Auth
	header := make([]byte, 24)
	header[0] = 0x80              // Magic: request
	header[1] = 0x21              // Opcode: SASL Auth
	binary.BigEndian.PutUint16(header[2:4], uint16(len(mechanism))) // Key length
	header[4] = 0                 // Extras length
	header[5] = 0                 // Data type
	binary.BigEndian.PutUint16(header[6:8], 0) // vbucket / status
	totalBody := len(mechanism) + len(authValue)
	binary.BigEndian.PutUint32(header[8:12], uint32(totalBody)) // Total body length
	binary.BigEndian.PutUint32(header[12:16], 0) // Opaque
	// CAS = 0 (bytes 16-23 already zeroed)

	// Send header + mechanism + auth value.
	packet := make([]byte, 0, 24+totalBody)
	packet = append(packet, header...)
	packet = append(packet, []byte(mechanism)...)
	packet = append(packet, authValue...)

	if _, err = conn.Write(packet); err != nil {
		return false, err
	}

	// Read response header (24 bytes).
	respHeader := make([]byte, 24)
	if _, err = readFull(conn, respHeader); err != nil {
		return false, err
	}

	if respHeader[0] != 0x81 { // Magic: response
		return false, nil
	}

	status := binary.BigEndian.Uint16(respHeader[6:8])

	// Status 0x0000 = success, 0x0020 = auth error, 0x0008 = auth error (older).
	switch status {
	case 0x0000:
		return true, nil
	case 0x0008, 0x0020:
		return false, nil
	default:
		return false, nil
	}
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
