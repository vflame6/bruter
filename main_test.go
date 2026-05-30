package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vflame6/bruter/scanner/modules"
)

func TestListServicesCLIPrintsSortedRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", ".", "--list-services")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("go run . --list-services failed: %v\nstderr:\n%s", err, stderr.String())
	}

	gotNames, gotPorts := parseListServicesOutput(t, stdout.String())
	wantNames := make([]string, 0, len(modules.Modules))
	for name := range modules.Modules {
		wantNames = append(wantNames, name)
	}
	sort.Strings(wantNames)

	if strings.Join(gotNames, ",") != strings.Join(wantNames, ",") {
		t.Fatalf("listed services mismatch\ngot:  %v\nwant: %v", gotNames, wantNames)
	}
	for _, name := range gotNames {
		if gotPorts[name] != modules.Modules[name].DefaultPort {
			t.Fatalf("%s port = %d, want %d", name, gotPorts[name], modules.Modules[name].DefaultPort)
		}
	}

	wantSummary := fmt.Sprintf("%d services available", len(modules.Modules))
	if !strings.Contains(stdout.String(), wantSummary) {
		t.Fatalf("missing summary %q in output:\n%s", wantSummary, stdout.String())
	}
}

func parseListServicesOutput(t *testing.T, output string) ([]string, map[string]int) {
	t.Helper()

	var names []string
	ports := make(map[string]int)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "SERVICE") || strings.HasPrefix(line, "-------") || strings.HasSuffix(line, "services available") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("unexpected --list-services line %q in output:\n%s", line, output)
		}
		port, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("service %s port %q is not numeric: %v", fields[0], fields[1], err)
		}
		names = append(names, fields[0])
		ports[fields[0]] = port
	}
	return names, ports
}
