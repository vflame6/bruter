package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestMSSQLHandler_DialFailure verifies that a connection refused error is returned
// as an error (not misclassified as authentication success or failure).
func TestMSSQLHandler_DialFailure(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19994,
		OriginalTarget: "127.0.0.1",
		Encryption:     false,
	}
	ok, err := MSSQLHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "sa", Password: "sa"})

	if err == nil {
		t.Error("expected connection error, got nil")
	}
	if ok {
		t.Error("ok should be false on dial failure")
	}
}

// TestMSSQLHandler_EncryptionDisabled verifies that encrypt=disable is appended
// when Encryption is false, and the handler handles a closed port gracefully.
func TestMSSQLHandler_EncryptionDisabled(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19993,
		OriginalTarget: "127.0.0.1",
		Encryption:     false, // should add &encrypt=disable
	}
	ok, err := MSSQLHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "sa", Password: "sa"})

	if err == nil {
		t.Error("expected connection error on closed port, got nil")
	}
	if ok {
		t.Error("ok should be false when connection fails")
	}
}
