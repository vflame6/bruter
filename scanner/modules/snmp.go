package modules

import (
	"context"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/vflame6/bruter/utils"
)

// SNMPHandler is an implementation of ModuleHandler for SNMP v1/v2c community string brute-force.
//
// NOTE: SNMP uses UDP; proxy support is unavailable for this module.
//
// credential.Username — SNMP v3 username; empty or "public" triggers v2c mode.
// credential.Password — community string (v1/v2c) or auth password (v3).
func SNMPHandler(_ context.Context, _ *utils.ProxyAwareDialer, timeout time.Duration, target *Target, credential *Credential) (bool, error) {
	g := &gosnmp.GoSNMP{
		Target:    target.IP.String(),
		Port:      uint16(target.Port), //nolint:gosec // port fits in uint16 by construction
		Community: credential.Password,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}

	if err := g.Connect(); err != nil {
		return false, err
	}
	defer func() { _ = g.Conn.Close() }()

	result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}) // sysDescr
	if err == nil && len(result.Variables) > 0 {
		return true, nil
	}
	// No response or empty result = wrong community string or device filtered SNMP.
	return false, nil
}
