package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// nessusReport is the root element of a .nessus file (NessusClientData_v2).
type nessusReport struct {
	XMLName xml.Name        `xml:"NessusClientData_v2"`
	Reports []nessusReportE `xml:"Report"`
}

type nessusReportE struct {
	Hosts []nessusHost `xml:"ReportHost"`
}

type nessusHost struct {
	Name  string       `xml:"name,attr"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusItem struct {
	Port    string `xml:"port,attr"`
	SvcName string `xml:"svc_name,attr"`
}

// ParseNessus parses a Nessus .nessus XML file and returns discovered targets.
func ParseNessus(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nessus: %w", err)
	}

	var report nessusReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("nessus parse: %w", err)
	}

	seen := make(map[string]struct{})
	var targets []Target

	for _, r := range report.Reports {
		for _, host := range r.Hosts {
			ip := host.Name
			if ip == "" {
				continue
			}
			for _, item := range host.Items {
				if item.Port == "0" || item.Port == "" {
					continue
				}
				port, err := strconv.Atoi(item.Port)
				if err != nil || port < 1 || port > 65535 {
					continue
				}

				service := strings.ToLower(item.SvcName)
				if service == "" || service == "general" || service == "unknown" {
					continue
				}

				// Map known Nessus service names (some differ from nmap)
				mapped := mapNessusService(service)
				mod, ok := MapService(mapped)
				if !ok {
					continue
				}

				key := fmt.Sprintf("%s:%d:%s", ip, port, mod)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}

				targets = append(targets, Target{Host: ip, Port: port, Service: mod})
			}
		}
	}

	return targets, nil
}

// mapNessusService normalizes Nessus-specific service names to nmap equivalents.
func mapNessusService(svc string) string {
	switch svc {
	case "www":
		return "http"
	case "cifs":
		return "microsoft-ds"
	case "ms-sql-s":
		return "ms-sql-s"
	case "ntp":
		return "ntp"
	default:
		return svc
	}
}
