package utils

import "crypto/tls"

var TLSConfig = &tls.Config{
	InsecureSkipVerify: true,
	MinVersion:         tls.VersionTLS10, // Allow older TLS for compatibility
}

func GetTLSConfig() *tls.Config {
	return TLSConfig
}
