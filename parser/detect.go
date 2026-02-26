package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Format represents a recognized scan output format.
type Format int

const (
	FormatUnknown Format = iota
	FormatGNMAP
	FormatXML
	FormatNessus
	FormatNexpose
)

// DetectFormat sniffs the first few lines of a file to determine whether
// it is GNMAP or XML format.
func DetectFormat(path string) (Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return FormatUnknown, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var xmlDetected bool
	for i := 0; i < 20 && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# Nmap") && strings.Contains(line, "scan") {
			return FormatGNMAP, nil
		}
		if strings.HasPrefix(line, "Host:") {
			return FormatGNMAP, nil
		}
		if strings.HasPrefix(line, "<?xml") || strings.HasPrefix(line, "<!DOCTYPE") {
			xmlDetected = true
			continue
		}
		if strings.HasPrefix(line, "<nmaprun") {
			return FormatXML, nil
		}
		if strings.HasPrefix(line, "<NessusClientData") {
			return FormatNessus, nil
		}
		if strings.HasPrefix(line, "<NexposeReport") || strings.HasPrefix(line, "<NeXposeSimpleXML") {
			return FormatNexpose, nil
		}
	}
	if xmlDetected {
		// XML but unknown root — could be nmap XML without nmaprun in first lines
		return FormatXML, nil
	}
	return FormatUnknown, nil
}

// ParseFile auto-detects the format and parses the nmap output file.
// Use forceFormat to override auto-detection (FormatGNMAP or FormatXML).
func ParseFile(path string, forceFormat Format) ([]Target, error) {
	format := forceFormat
	if format == FormatUnknown {
		var err error
		format, err = DetectFormat(path)
		if err != nil {
			return nil, err
		}
	}

	switch format {
	case FormatGNMAP:
		return ParseGNMAP(path)
	case FormatXML:
		return ParseXML(path)
	case FormatNessus:
		return ParseNessus(path)
	case FormatNexpose:
		return ParseNexpose(path)
	default:
		return nil, fmt.Errorf("unable to detect scan output format for %s; supported: nmap (GNMAP/XML), Nessus (.nessus), Nexpose XML", path)
	}
}
