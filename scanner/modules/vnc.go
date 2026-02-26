package modules

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vflame6/bruter/utils"
)

// VNC RFB security types
const (
	vncSecNone     = 1
	vncSecVNCAuth  = 2
)

// VNC auth results
const (
	vncAuthOK     = 0
	vncAuthFailed = 1
)

// reverseBits reverses the bit order of a byte.
// VNC DES uses reversed key bits per the RFB spec.
func reverseBits(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		r = (r << 1) | (b & 1)
		b >>= 1
	}
	return r
}

// vncDESKey converts a password into an 8-byte DES key with reversed bits,
// as required by the VNC RFB authentication protocol.
func vncDESKey(password string) []byte {
	key := make([]byte, 8)
	for i := 0; i < len(password) && i < 8; i++ {
		key[i] = reverseBits(password[i])
	}
	return key
}

// VNCHandler is an implementation of ModuleHandler for VNC RFB password authentication.
// The credential.Username is ignored — VNC uses only a password.
//
// Implements the VNC RFB 3.x authentication handshake:
// 1. Read server protocol version, respond with client version
// 2. Read security types, select VNC Authentication (type 2)
// 3. Read 16-byte challenge, encrypt with DES using password as key
// 4. Send response, read 4-byte auth result
func VNCHandler(ctx context.Context, dialer *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	addr := target.Addr()

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Step 1: Protocol version handshake
	verBuf := make([]byte, 12)
	if _, err := io.ReadFull(conn, verBuf); err != nil {
		return false, fmt.Errorf("vnc: read server version: %w", err)
	}

	serverVer := string(verBuf)
	// Support RFB 3.3, 3.7, 3.8
	var major, minor int
	if _, err := fmt.Sscanf(serverVer, "RFB %d.%d\n", &major, &minor); err != nil {
		return false, fmt.Errorf("vnc: invalid server version: %q", serverVer)
	}

	// Respond with 3.8 if server supports it, otherwise match server
	clientVer := "RFB 003.008\n"
	if major < 3 || (major == 3 && minor < 7) {
		clientVer = fmt.Sprintf("RFB %03d.%03d\n", major, minor)
	}
	if _, err := conn.Write([]byte(clientVer)); err != nil {
		return false, fmt.Errorf("vnc: write client version: %w", err)
	}

	// Step 2: Security handshake (differs by version)
	if major == 3 && minor < 7 {
		// RFB 3.3: server sends a single uint32 security type
		var secType uint32
		if err := binary.Read(conn, binary.BigEndian, &secType); err != nil {
			return false, fmt.Errorf("vnc: read security type: %w", err)
		}
		if secType == 0 {
			// Connection failed — read reason
			return false, readFailureReason(conn)
		}
		if secType != vncSecVNCAuth {
			return false, fmt.Errorf("vnc: server requires security type %d, not VNC auth", secType)
		}
	} else {
		// RFB 3.7+: server sends list of security types
		var numTypes uint8
		if err := binary.Read(conn, binary.BigEndian, &numTypes); err != nil {
			return false, fmt.Errorf("vnc: read num security types: %w", err)
		}
		if numTypes == 0 {
			return false, readFailureReason(conn)
		}

		types := make([]byte, numTypes)
		if _, err := io.ReadFull(conn, types); err != nil {
			return false, fmt.Errorf("vnc: read security types: %w", err)
		}

		found := false
		for _, t := range types {
			if t == vncSecVNCAuth {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("vnc: server does not support VNC authentication")
		}

		// Select VNC Authentication
		if _, err := conn.Write([]byte{vncSecVNCAuth}); err != nil {
			return false, fmt.Errorf("vnc: write security selection: %w", err)
		}
	}

	// Step 3: VNC Authentication — DES challenge-response
	challenge := make([]byte, 16)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return false, fmt.Errorf("vnc: read challenge: %w", err)
	}

	key := vncDESKey(credential.Password)
	cipher, err := des.NewCipher(key)
	if err != nil {
		return false, fmt.Errorf("vnc: create DES cipher: %w", err)
	}

	response := make([]byte, 16)
	cipher.Encrypt(response[0:8], challenge[0:8])
	cipher.Encrypt(response[8:16], challenge[8:16])

	if _, err := conn.Write(response); err != nil {
		return false, fmt.Errorf("vnc: write response: %w", err)
	}

	// Step 4: Read auth result
	var result uint32
	if err := binary.Read(conn, binary.BigEndian, &result); err != nil {
		return false, fmt.Errorf("vnc: read auth result: %w", err)
	}

	switch result {
	case vncAuthOK:
		return true, nil
	case vncAuthFailed:
		return false, nil
	default:
		// Some servers send result=2 for "too many attempts"
		return false, nil
	}
}

// readFailureReason reads a uint32 length-prefixed reason string from the connection.
func readFailureReason(r io.Reader) error {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("vnc: connection failed (could not read reason)")
	}
	if length > 4096 {
		length = 4096
	}
	reason := make([]byte, length)
	if _, err := io.ReadFull(r, reason); err != nil {
		return fmt.Errorf("vnc: connection failed (could not read reason)")
	}
	return fmt.Errorf("vnc: server refused: %s", strings.TrimSpace(string(reason)))
}
