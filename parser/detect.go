package parser

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Format represents a recognized nmap output format.
type Format int

const (
	FormatUnknown Format = iota
	FormatGNMAP
	FormatXML
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
	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "<?xml") || strings.HasPrefix(line, "<nmaprun") {
			return FormatXML, nil
		}
		if strings.HasPrefix(line, "# Nmap") && strings.Contains(line, "scan") {
			return FormatGNMAP, nil
		}
		if strings.HasPrefix(line, "Host:") {
			return FormatGNMAP, nil
		}
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
	default:
		return nil, fmt.Errorf("unable to detect nmap output format for %s; use --nmap-gnmap or --nmap-xml to specify", path)
	}
}
