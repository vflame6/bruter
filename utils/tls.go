package utils

import "crypto/tls"

var TLSConfig = &tls.Config{
	InsecureSkipVerify: true,
	MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
}

// GetTLSConfig returns a clone of the base TLS config so each caller
// can safely mutate fields (e.g. ServerName) without racing other callers.
func GetTLSConfig() *tls.Config {
	return TLSConfig.Clone()
}
