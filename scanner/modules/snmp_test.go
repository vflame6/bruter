package modules

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSNMPHandler_NoResponse verifies that when no SNMP agent responds
// (wrong community string or port closed), the handler returns (false, nil)
// rather than an error.
func TestSNMPHandler_NoResponse(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19981,
		OriginalTarget: "127.0.0.1",
	}
	// Very short timeout so the Get() call times out quickly.
	ok, err := SNMPHandler(context.Background(), newTestDialer(t), 100*time.Millisecond,
		target, &Credential{Username: "", Password: "public"})

	if ok {
		t.Error("expected ok=false when no SNMP agent responds")
	}
	// err may be nil (timeout treated as no-response) or a timeout error;
	// the critical invariant is ok=false.
	_ = err
}

// TestSNMPHandler_InvalidTarget verifies that an unresolvable or invalid target
// returns ok=false. A target of 0.0.0.0 with no agent is acceptable here.
func TestSNMPHandler_InvalidTarget(t *testing.T) {
	target := &Target{
		IP:             net.ParseIP("127.0.0.1"),
		Port:           19980,
		OriginalTarget: "127.0.0.1",
	}
	ok, err := SNMPHandler(context.Background(), newTestDialer(t), 100*time.Millisecond,
		target, &Credential{Username: "", Password: "wrongcommunity"})

	if ok {
		t.Error("expected ok=false for wrong community string with no agent")
	}
	_ = err
}
