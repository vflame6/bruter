package parser

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vflame6/bruter/scanner/modules"
)

// updateGolden rewrites the expected output files instead of comparing against
// them. Run `go test ./parser -update` after an intentional parser change, then
// review the diff in parser/testdata/golden before committing it.
var updateGolden = flag.Bool("update", false, "rewrite parser golden files")

// goldenCases pairs each sample scan with the format it must be detected as.
// The samples live in parser/testdata and are trimmed-down but structurally
// faithful exports from nmap 7.95, Nessus and Nexpose.
var goldenCases = []struct {
	file   string
	format Format
}{
	{file: "nmap-sv.gnmap", format: FormatGNMAP},
	{file: "nmap-sv.xml", format: FormatXML},
	{file: "nessus-report.nessus", format: FormatNessus},
	{file: "nexpose-report.xml", format: FormatNexpose},
}

func TestDetectFormatGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := DetectFormat(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatalf("DetectFormat: %v", err)
			}
			if got != tc.format {
				t.Errorf("DetectFormat(%s) = %d, want %d", tc.file, got, tc.format)
			}
		})
	}
}

func TestParseFileGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.file, func(t *testing.T) {
			targets, err := ParseFile(filepath.Join("testdata", tc.file), FormatUnknown)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}

			got, err := json.MarshalIndent(targets, "", "  ")
			if err != nil {
				t.Fatalf("marshal targets: %v", err)
			}
			got = append(got, '\n')

			goldenPath := filepath.Join("testdata", "golden", tc.file+".json")
			if *updateGolden {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("updated %s", goldenPath)
				return
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden (run `go test ./parser -update` to create it): %v", err)
			}

			// .gitattributes pins these to LF, but a checkout configured with
			// core.autocrlf would still hand us CRLF, and that is not a parser
			// regression.
			if normalizeEOL(string(got)) != normalizeEOL(string(want)) {
				t.Errorf("parsed targets differ from %s\n%s", goldenPath, lineDiff(string(want), string(got)))
			}
		})
	}
}

// TestServiceMapTargetsRealModules guards the other half of the scan-import
// feature: a service name may only map to a module the scanner can actually
// run, otherwise imported targets are silently dropped at dispatch time.
func TestServiceMapTargetsRealModules(t *testing.T) {
	for nmapName, moduleName := range serviceMap {
		if _, ok := modules.Modules[moduleName]; !ok {
			t.Errorf("serviceMap[%q] = %q, which is not a registered module", nmapName, moduleName)
		}
	}
}

// TestGoldenFilesCoverEveryFormat fails if a new scan format is added to the
// parser without a sample scan and golden file to go with it.
func TestGoldenFilesCoverEveryFormat(t *testing.T) {
	covered := make(map[Format]bool, len(goldenCases))
	for _, tc := range goldenCases {
		covered[tc.format] = true
	}
	for _, f := range []Format{FormatGNMAP, FormatXML, FormatNessus, FormatNexpose} {
		if !covered[f] {
			t.Errorf("format %d has no golden-file case", f)
		}
	}
}

// normalizeEOL strips carriage returns so a CRLF checkout compares equal.
func normalizeEOL(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// lineDiff renders the first differing line plus both full bodies, which is
// enough to tell an intentional parser change from a regression.
func lineDiff(want, got string) string {
	wantLines := strings.Split(normalizeEOL(want), "\n")
	gotLines := strings.Split(normalizeEOL(got), "\n")

	var b strings.Builder
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w != g {
			b.WriteString("first difference at line ")
			b.WriteString(strconv.Itoa(i + 1))
			b.WriteString(":\n  want: ")
			b.WriteString(w)
			b.WriteString("\n  got:  ")
			b.WriteString(g)
			b.WriteString("\n")
			break
		}
	}
	b.WriteString("\n--- want ---\n")
	b.WriteString(want)
	b.WriteString("--- got ---\n")
	b.WriteString(got)
	return b.String()
}
