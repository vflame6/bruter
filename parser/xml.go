package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// nmapRun is the root element of nmap XML output.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name   string `xml:"name,attr"`
	Tunnel string `xml:"tunnel,attr"`
}

// ParseXML parses an nmap XML output file (-oX) and returns discovered targets.
func ParseXML(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nmap xml: %w", err)
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("nmap xml parse: %w", err)
	}

	var targets []Target

	for _, host := range run.Hosts {
		addr := hostAddress(host.Addresses)
		if addr == "" {
			continue
		}

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			if port.PortID < 1 || port.PortID > 65535 {
				continue
			}

			service := strings.ToLower(port.Service.Name)

			if service == "" || service == "unknown" {
				continue
			}

			// If tunnel="ssl", try the SSL variant first (e.g. "http" with ssl → "https")
			if port.Service.Tunnel == "ssl" {
				sslService := service + "s"
				if mod, ok := MapService(sslService); ok {
					targets = append(targets, Target{Host: addr, Port: port.PortID, Service: mod})
					continue
				}
			}

			mod, ok := MapService(service)
			if !ok {
				continue
			}

			targets = append(targets, Target{Host: addr, Port: port.PortID, Service: mod})
		}
	}

	return targets, nil
}

// hostAddress returns the best address (prefer IPv4) from a host's address list.
func hostAddress(addrs []nmapAddress) string {
	var ipv4, ipv6, other string
	for _, a := range addrs {
		switch a.AddrType {
		case "ipv4":
			ipv4 = a.Addr
		case "ipv6":
			ipv6 = a.Addr
		default:
			if other == "" {
				other = a.Addr
			}
		}
	}
	if ipv4 != "" {
		return ipv4
	}
	if ipv6 != "" {
		return ipv6
	}
	return other
}
