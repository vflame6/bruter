package parser

import (
	"strings"
	"testing"
)

func TestParseStdin_FingerprintxJSON(t *testing.T) {
	input := `{"host":"192.168.1.1","port":22,"service":"ssh","transport":"tcp"}
{"host":"192.168.1.2","port":3306,"service":"mysql","transport":"tcp"}
{"host":"10.0.0.1","port":445,"service":"smb","transport":"tcp"}`

	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}

	expected := []struct {
		host    string
		port    int
		service string
	}{
		{"192.168.1.1", 22, "ssh"},
		{"192.168.1.2", 3306, "mysql"},
		{"10.0.0.1", 445, "smb"},
	}

	for i, e := range expected {
		if targets[i].Host != e.host || targets[i].Port != e.port || targets[i].Service != e.service {
			t.Errorf("target[%d] = %+v, want host=%s port=%d service=%s", i, targets[i], e.host, e.port, e.service)
		}
	}
}

func TestParseStdin_NaabuJSON(t *testing.T) {
	// naabu has no service field — should use port mapping
	input := `{"host":"10.0.0.5","port":22}
{"host":"10.0.0.5","port":3389}`

	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Service != "ssh" {
		t.Errorf("expected ssh for port 22, got %s", targets[0].Service)
	}
	if targets[1].Service != "rdp" {
		t.Errorf("expected rdp for port 3389, got %s", targets[1].Service)
	}
}

func TestParseStdin_PlainText(t *testing.T) {
	input := `192.168.1.1:22
10.0.0.1:3306
10.0.0.2:5432`

	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0].Service != "ssh" {
		t.Errorf("expected ssh, got %s", targets[0].Service)
	}
	if targets[1].Service != "mysql" {
		t.Errorf("expected mysql, got %s", targets[1].Service)
	}
	if targets[2].Service != "postgres" {
		t.Errorf("expected postgres, got %s", targets[2].Service)
	}
}

func TestParseStdin_MixedFormats(t *testing.T) {
	input := `{"host":"10.0.0.1","port":22,"service":"ssh"}
192.168.1.1:3306
{"ip":"10.0.0.2","port":445}

`

	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
}

func TestParseStdin_EmptyInput(t *testing.T) {
	targets, err := ParseStdin(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(targets))
	}
}

func TestParseStdin_UnknownPort(t *testing.T) {
	// Port 12345 has no mapping — should be skipped
	input := `192.168.1.1:12345`
	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("expected 0 targets (unknown port), got %d", len(targets))
	}
}

func TestParseStdin_IPv6PlainText(t *testing.T) {
	// IPv6 with brackets
	input := `[::1]:22`
	targets, err := ParseStdin(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}
	if targets[0].Host != "[::1]" || targets[0].Port != 22 {
		t.Errorf("got %+v", targets[0])
	}
}
