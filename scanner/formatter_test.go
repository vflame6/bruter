package scanner

import (
	"net"
	"testing"
)

func TestParseTarget(t *testing.T) {
	const defaultPort = 22

	tests := []struct {
		name         string
		input        string
		wantIP       string // empty = expect error
		wantPort     int
		wantOriginal string
		wantErr      bool
	}{
		// IPv4 bare
		{
			name:         "bare IPv4",
			input:        "1.2.3.4",
			wantIP:       "1.2.3.4",
			wantPort:     defaultPort,
			wantOriginal: "1.2.3.4",
		},
		// IPv4 with port
		{
			name:         "IPv4 with port",
			input:        "1.2.3.4:22",
			wantIP:       "1.2.3.4",
			wantPort:     22,
			wantOriginal: "1.2.3.4:22",
		},
		// IPv4 with non-default port
		{
			name:         "IPv4 with non-default port",
			input:        "192.168.1.1:8080",
			wantIP:       "192.168.1.1",
			wantPort:     8080,
			wantOriginal: "192.168.1.1:8080",
		},
		// IPv6 bare loopback
		{
			name:         "bare IPv6 loopback",
			input:        "::1",
			wantIP:       "::1",
			wantPort:     defaultPort,
			wantOriginal: "::1",
		},
		// IPv6 with port in bracket notation
		{
			name:         "bracketed IPv6 with port",
			input:        "[::1]:22",
			wantIP:       "::1",
			wantPort:     22,
			wantOriginal: "[::1]:22",
		},
		// Full IPv6 address bare
		{
			name:         "bare full IPv6",
			input:        "2001:db8::1",
			wantIP:       "2001:db8::1",
			wantPort:     defaultPort,
			wantOriginal: "2001:db8::1",
		},
		// Full IPv6 with port
		{
			name:         "bracketed full IPv6 with port",
			input:        "[2001:db8::1]:443",
			wantIP:       "2001:db8::1",
			wantPort:     443,
			wantOriginal: "[2001:db8::1]:443",
		},
		// OriginalTarget preserved (not overwritten by resolved IP)
		{
			name:         "OriginalTarget preserved as raw input",
			input:        "127.0.0.1:9200",
			wantIP:       "127.0.0.1",
			wantPort:     9200,
			wantOriginal: "127.0.0.1:9200",
		},
		// Error cases
		{
			name:    "port out of range high",
			input:   "1.2.3.4:99999",
			wantErr: true,
		},
		{
			name:    "port zero",
			input:   "1.2.3.4:0",
			wantErr: true,
		},
		{
			name:    "non-numeric port",
			input:   "1.2.3.4:abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.input, defaultPort)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseTarget(%q) expected error, got nil (result: %+v)", tt.input, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseTarget(%q) unexpected error: %v", tt.input, err)
			}

			wantIP := net.ParseIP(tt.wantIP)
			if !got.IP.Equal(wantIP) {
				t.Errorf("ParseTarget(%q).IP = %v, want %v", tt.input, got.IP, wantIP)
			}

			if got.Port != tt.wantPort {
				t.Errorf("ParseTarget(%q).Port = %d, want %d", tt.input, got.Port, tt.wantPort)
			}

			if got.OriginalTarget != tt.wantOriginal {
				t.Errorf("ParseTarget(%q).OriginalTarget = %q, want %q", tt.input, got.OriginalTarget, tt.wantOriginal)
			}

			if !got.Encryption {
				t.Errorf("ParseTarget(%q).Encryption = false, want true", tt.input)
			}
		})
	}
}
