package modules

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// mockRTSPServer starts a minimal RTSP server for one connection.
// It responds with the given status code to any DESCRIBE request.
func mockRTSPServer(t *testing.T, statusCode int, statusText string) (string, int) {
	t.Helper()
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
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read request (drain until double CRLF).
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			data := string(buf[:n])
			if containsStr(data, "\r\n\r\n") {
				break
			}
		}
		_, _ = fmt.Fprintf(conn, "RTSP/1.0 %d %s\r\nCSeq: 1\r\n\r\n", statusCode, statusText)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port
}

func TestRTSPHandler_Success(t *testing.T) {
	host, port := mockRTSPServer(t, 200, "OK")
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RTSPHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "admin"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected ok=true for RTSP 200 OK")
	}
}

func TestRTSPHandler_Unauthorized(t *testing.T) {
	host, port := mockRTSPServer(t, 401, "Unauthorized")
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RTSPHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "wrong"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for RTSP 401 Unauthorized")
	}
}

func TestRTSPHandler_Forbidden(t *testing.T) {
	host, port := mockRTSPServer(t, 403, "Forbidden")
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RTSPHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "wrong"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for RTSP 403 Forbidden")
	}
}

func TestRTSPHandler_UnexpectedStatus(t *testing.T) {
	host, port := mockRTSPServer(t, 500, "Internal Server Error")
	target := &Target{IP: net.ParseIP(host), Port: port, OriginalTarget: host}
	ok, err := RTSPHandler(context.Background(), newTestDialer(t), 3*time.Second,
		target, &Credential{Username: "admin", Password: "admin"})
	if err == nil {
		t.Error("expected error for unexpected status code")
	}
	if ok {
		t.Error("expected ok=false for unexpected status")
	}
}

func TestRTSPHandler_DialFailure(t *testing.T) {
	target := &Target{IP: net.ParseIP("127.0.0.1"), Port: 19976, OriginalTarget: "127.0.0.1"}
	_, err := RTSPHandler(context.Background(), newTestDialer(t), 500*time.Millisecond,
		target, &Credential{Username: "admin", Password: "admin"})
	if err == nil {
		t.Error("expected connection error, got nil")
	}
}
