package utils

import (
	"net"
	"testing"
)

// loopbackIface finds the loopback interface on this machine. The name is
// discovered rather than hard-coded, because it is "lo" on Linux, "lo0" on
// macOS and something like "Loopback Pseudo-Interface 1" on Windows.
func loopbackIface(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface.Name
			}
		}
	}

	t.Skip("no loopback interface with an IPv4 address")
	return ""
}

func TestGetInterfaceIPv4_Loopback(t *testing.T) {
	name := loopbackIface(t)
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

func TestGetInterfaceIPv4_LoopbackDetectedByFlagNotName(t *testing.T) {
	// The loopback interface is "lo" on Linux, "lo0" on macOS and
	// "Loopback Pseudo-Interface 1" on Windows, and it can be renamed on any
	// of them. Deciding from the name meant 127.0.0.1 was discarded as "a
	// loopback address on a non-loopback interface" everywhere else.
	name := loopbackIface(t)

	ip, err := GetInterfaceIPv4(name)
	if err != nil {
		t.Fatalf("GetInterfaceIPv4(%q): %v", name, err)
	}
	if !ip.IsLoopback() {
		t.Errorf("GetInterfaceIPv4(%q) = %v, want a loopback address", name, ip)
	}

	// The converse still has to hold: a non-loopback interface must not hand
	// back a loopback address.
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		got, err := GetInterfaceIPv4(iface.Name)
		if err != nil {
			continue // no IPv4 on this one, which is fine
		}
		if got.IsLoopback() {
			t.Errorf("GetInterfaceIPv4(%q) returned loopback %v from a non-loopback interface", iface.Name, got)
		}
	}
}
