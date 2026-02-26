package parser

import (
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// nexposeNode represents a host in Nexpose XML export.
type nexposeNode struct {
	Address   string             `xml:"address,attr"`
	Endpoints []nexposeEndpoint  `xml:"endpoints>endpoint"`
}

type nexposeEndpoint struct {
	Port     string          `xml:"port,attr"`
	Status   string          `xml:"status,attr"`
	Protocol string          `xml:"protocol,attr"`
	Services []nexposeService `xml:"services>service"`
}

type nexposeService struct {
	Name string `xml:"name,attr"`
}

// ParseNexpose parses a Nexpose XML export file and returns discovered targets.
func ParseNexpose(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nexpose: %w", err)
	}

	// Nexpose XML has <nodes><node>...</node></nodes> structure.
	// We use streaming decode to find <node> elements at any depth.
	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	var nodes []nexposeNode
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if se, ok := token.(xml.StartElement); ok && se.Name.Local == "node" {
			var node nexposeNode
			if err := decoder.DecodeElement(&node, &se); err != nil {
				return nil, fmt.Errorf("nexpose parse node: %w", err)
			}
			nodes = append(nodes, node)
		}
	}

	seen := make(map[string]struct{})
	var targets []Target

	for _, node := range nodes {
		ip := node.Address
		if ip == "" {
			continue
		}
		for _, ep := range node.Endpoints {
			if ep.Status != "open" {
				continue
			}
			port, err := strconv.Atoi(ep.Port)
			if err != nil || port < 1 || port > 65535 {
				continue
			}

			for _, svc := range ep.Services {
				service := strings.ToLower(svc.Name)
				if service == "" || service == "unknown" {
					continue
				}

				mod, ok := MapService(service)
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
