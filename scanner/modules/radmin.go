package modules

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"time"

	"github.com/vflame6/bruter/utils"
)

// RadminHandler is an implementation of ModuleHandler for Radmin 2.x (port 4899).
// Implements the Radmin challenge-response authentication protocol.
// Password-only auth (username is ignored).
//
// Protocol flow:
// 1. Send challenge request (magic=0x01, len=0x01, type=0x1b)
// 2. Receive 32-byte challenge
// 3. Compute MD5(password) → MD5(MD5(password) + challenge) = response
// 4. Send response (magic=0x01, len=0x21, type=0x09, data=32-byte response)
// 5. Check reply type: 0x05 = success, other = failure
func RadminHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialAutoContext(ctx, "tcp", addr, target.Encryption)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: Send challenge request.
	// Format: magic(1) + length(4 BE) + checksum(4 BE) + type(1) = 10 bytes
	challengeReq := buildRadminMessage(0x1b, nil)
	if _, err = conn.Write(challengeReq); err != nil {
		return false, err
	}

	// Step 2: Read challenge response — expect 10-byte header + 32-byte challenge data.
	respBuf := make([]byte, 128)
	n, err := conn.Read(respBuf)
	if err != nil {
		return false, err
	}
	if n < 42 { // 10 header + 32 challenge
		return false, nil
	}

	// Extract 32-byte challenge from the data section (after 10-byte header).
	challenge := respBuf[10:42]

	// Step 3: Compute response.
	// MD5 the password to get a 16-byte hash, then pad to 32 bytes with zeros.
	passHash := md5.Sum([]byte(credential.Password))
	// Concatenate passHash (padded to 32 bytes) + challenge (32 bytes).
	combined := make([]byte, 64)
	copy(combined[:16], passHash[:])
	// Bytes 16-31 stay zero (padding).
	copy(combined[32:], challenge)
	// MD5 of combined → 16 bytes, pad to 32.
	responseHash := md5.Sum(combined)
	responsePadded := make([]byte, 32)
	copy(responsePadded[:16], responseHash[:])

	// Step 4: Send challenge response.
	authMsg := buildRadminMessage(0x09, responsePadded)
	if _, err = conn.Write(authMsg); err != nil {
		return false, err
	}

	// Step 5: Read final response.
	n, err = conn.Read(respBuf)
	if err != nil {
		return false, err
	}
	if n < 10 {
		return false, nil
	}

	// Type byte at offset 9: 0x05 = success.
	if respBuf[9] == 0x05 {
		return true, nil
	}
	return false, nil
}

// buildRadminMessage constructs a Radmin 2.x protocol message.
// Format: magic(1) + length(4 big-endian) + checksum(4 big-endian) + type(1) + data
func buildRadminMessage(msgType byte, data []byte) []byte {
	length := uint32(1 + len(data)) // type + data

	msg := make([]byte, 10+len(data))
	msg[0] = 0x01 // magic

	binary.BigEndian.PutUint32(msg[1:5], length)

	// Build checksum: sum of all 4-byte words in (type + data), zero-padded.
	checksumData := make([]byte, 0, 1+len(data))
	checksumData = append(checksumData, msgType)
	checksumData = append(checksumData, data...)
	// Pad to 4-byte alignment.
	for len(checksumData)%4 != 0 {
		checksumData = append(checksumData, 0)
	}
	var checksum uint32
	for i := 0; i < len(checksumData); i += 4 {
		checksum += binary.BigEndian.Uint32(checksumData[i : i+4])
	}
	binary.BigEndian.PutUint32(msg[5:9], checksum)

	msg[9] = msgType
	copy(msg[10:], data)

	return msg
}
