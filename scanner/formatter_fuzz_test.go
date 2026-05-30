package scanner

import "testing"

func FuzzParseTarget(f *testing.F) {
	// Seed corpus: valid formats
	f.Add("127.0.0.1", 22)
	f.Add("127.0.0.1:8080", 22)
	f.Add("::1", 22)
	f.Add("[::1]:443", 80)
	f.Add("example.com", 22)
	f.Add("example.com:8080", 22)
	f.Add("[2001:db8::1]:22", 22)

	// Edge cases
	f.Add("", 22)
	f.Add(":", 22)
	f.Add(":22", 22)
	f.Add("[]:22", 22)
	f.Add("127.0.0.1:0", 22)
	f.Add("127.0.0.1:99999", 22)
	f.Add("127.0.0.1:-1", 22)
	f.Add("[::1]", 22)
	f.Add("a:b:c", 22)
	f.Add("999.999.999.999", 22)
	f.Add("localhost", 0)
	f.Add("127.0.0.1:abc", 22)

	f.Fuzz(func(t *testing.T, target string, defaultPort int) {
		// Must not panic — errors are fine
		_, _ = ParseTarget(target, defaultPort)
	})
}
