package utils

import (
	"net"
	"runtime"
	"testing"
)

// loopbackIface returns the loopback interface name for the current OS.
func loopbackIface() string {
	if runtime.GOOS == "darwin" {
		return "lo0"
	}
	return "lo"
}

func TestGetInterfaceIPv4_Loopback(t *testing.T) {
	name := loopbackIface()
	ip, err := GetInterfaceIPv4(name)
	if err != nil {
		t.Fatalf("GetInterfaceIPv4(%q) unexpected error: %v", name, err)
	}
	if ip == nil {
		t.Fatalf("GetInterfaceIPv4(%q) returned nil IP", name)
	}
	want := net.ParseIP("127.0.0.1")
	if !ip.Equal(want) {
		t.Errorf("GetInterfaceIPv4(%q) = %v, want 127.0.0.1", name, ip)
	}
}

func TestGetInterfaceIPv4_NonexistentInterface(t *testing.T) {
	_, err := GetInterfaceIPv4("nonexistent_iface_xyz_123")
	if err == nil {
		t.Error("GetInterfaceIPv4(\"nonexistent_iface_xyz_123\") expected error, got nil")
	}
}

func TestGetInterfaceIPv4_EmptyName(t *testing.T) {
	_, err := GetInterfaceIPv4("")
	if err == nil {
		t.Error("GetInterfaceIPv4(\"\") expected error, got nil")
	}
}
