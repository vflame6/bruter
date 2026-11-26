package utils

import (
	"fmt"
	"net"
)

// GetInterfaceIPv4 returns the first IPv4 address bound to the named network interface.
// On a loopback interface, loopback addresses (127.x.x.x) are included; on any
// other interface they are skipped.
// Returns an error if the interface does not exist or has no matching IPv4 address.
func GetInterfaceIPv4(name string) (net.IP, error) {
	if name == "" {
		return nil, fmt.Errorf("interface name is empty")
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", name, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %q: %w", name, err)
	}

	// Ask the interface, rather than guessing from its name. Loopback is "lo"
	// on Linux and "lo0" on macOS, but "Loopback Pseudo-Interface 1" on
	// Windows, and on any platform it can be renamed.
	isLoopbackIface := iface.Flags&net.FlagLoopback != 0

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip == nil {
			continue
		}

		ipv4 := ip.To4()
		if ipv4 == nil {
			continue // skip non-IPv4
		}

		if ip.IsLoopback() && !isLoopbackIface {
			continue // skip loopback unless interface is lo/lo0
		}

		return ipv4, nil
	}

	return nil, fmt.Errorf("no IPv4 address found on interface %q", name)
}
