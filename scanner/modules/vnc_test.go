package modules

import (
	"context"
	"crypto/des"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// TestVNCHandler_DialFailure verifies that a connection refused error is returned
// as an error (not misclassified as authentication success or failure).
func TestVNCHandler_DialFailure(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19986,
		OriginalTarget: "127.0.0.1",
		Encryption:     false,
	}
	ok, err := VNCHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "", Password: "admin"})

	if err == nil {
		t.Error("expected connection error, got nil")
	}
	if ok {
		t.Error("ok should be false on dial failure")
	}
}

// TestVNCHandler_ImmediateClose verifies that a server that closes the connection
// before completing the VNC handshake is not treated as auth success.
func TestVNCHandler_ImmediateClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
	}
	ok, err := VNCHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "admin"})

	if ok {
		t.Error("ok should be false when server closes connection immediately")
	}
	_ = err // protocol or EOF error expected; key invariant is ok=false
}

// fakeVNCServer simulates a VNC server with RFB 3.8 protocol.
// It accepts one connection, performs the handshake, and returns authOK
// if the DES challenge-response matches the expected password.
func fakeVNCServer(t *testing.T, ln net.Listener, password string) {
	t.Helper()
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	// Send server version
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}

	// Read client version
	clientVer := make([]byte, 12)
	if _, err := io.ReadFull(conn, clientVer); err != nil {
		return
	}

	// Send security types: only VNC Auth (type 2)
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		return
	}

	// Read client security selection
	sel := make([]byte, 1)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return
	}
	if sel[0] != 2 {
		return
	}

	// Send 16-byte challenge
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	if _, err := conn.Write(challenge); err != nil {
		return
	}

	// Read 16-byte response
	response := make([]byte, 16)
	if _, err := io.ReadFull(conn, response); err != nil {
		return
	}

	// Compute expected response
	key := vncDESKey(password)
	cipher, _ := des.NewCipher(key)
	expected := make([]byte, 16)
	cipher.Encrypt(expected[0:8], challenge[0:8])
	cipher.Encrypt(expected[8:16], challenge[8:16])

	var result uint32
	match := true
	for i := range response {
		if response[i] != expected[i] {
			match = false
			break
		}
	}
	if match {
		result = 0 // OK
	} else {
		result = 1 // Failed
	}

	_ = binary.Write(conn, binary.BigEndian, result)
}

func TestVNCHandler_CorrectPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go fakeVNCServer(t, ln, "secret")

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
	}
	ok, err := VNCHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "secret"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for correct password")
	}
}

func TestVNCHandler_WrongPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go fakeVNCServer(t, ln, "secret")

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
	}
	ok, err := VNCHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "wrong"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for wrong password")
	}
}

func TestVNCHandler_RFB33(t *testing.T) {
	// Test RFB 3.3 protocol path (server sends single uint32 security type)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// RFB 3.3
		conn.Write([]byte("RFB 003.003\n"))
		clientVer := make([]byte, 12)
		io.ReadFull(conn, clientVer)

		// Send security type as uint32
		binary.Write(conn, binary.BigEndian, uint32(2))

		// Challenge
		challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		conn.Write(challenge)

		// Read response
		response := make([]byte, 16)
		io.ReadFull(conn, response)

		// Always return OK for this test
		binary.Write(conn, binary.BigEndian, uint32(0))
	}()

	addr := ln.Addr().(*net.TCPAddr)
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           addr.Port,
		OriginalTarget: "127.0.0.1",
	}
	ok, err := VNCHandler(context.Background(), newTestDialer(t), 2*time.Second,
		target, &Credential{Username: "", Password: "test"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true")
	}
}

func TestReverseBits(t *testing.T) {
	tests := []struct {
		in, out byte
	}{
		{0b10000000, 0b00000001},
		{0b11110000, 0b00001111},
		{0b10101010, 0b01010101},
		{0xFF, 0xFF},
		{0x00, 0x00},
	}
	for _, tt := range tests {
		got := reverseBits(tt.in)
		if got != tt.out {
			t.Errorf("reverseBits(0x%02x) = 0x%02x, want 0x%02x", tt.in, got, tt.out)
		}
	}
}
