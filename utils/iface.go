package utils

import (
	"fmt"
	"net"
)

// GetInterfaceIPv4 returns the first IPv4 address bound to the named network interface.
// For loopback interfaces ("lo", "lo0") loopback addresses (127.x.x.x) are included.
// For all other interfaces loopback addresses are skipped.
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

	isLoopbackIface := name == "lo" || name == "lo0"

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
