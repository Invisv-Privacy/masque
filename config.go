// Package masque implements a client-side IETF MASQUE protocol stack.
package masque

import "time"

// MaxTLSTrials is the number of attempts made when establishing a TLS connection to a proxy.
var MaxTLSTrials int = 10

// MaxTLSDialTimeout is the maximum time duration, in milliseconds, allowed for establishing a TLS connection to the proxy.
// This variable is set to 2000 milliseconds by default.
var MaxTLSDialTimeout time.Duration = time.Duration(2000 * time.Millisecond)

// List of destination ports Fastly's Proxy B blocks
// Only exception is UDP port 53.
var disallowedPorts []uint16 = []uint16{0, 19, 25, 123, 161, 162, 179, 1900, 3283, 5353, 11211}

const (
	MAX_DISALLOWED_PORT_NUM = 11211
)

var disallowedPortsBitset [MAX_DISALLOWED_PORT_NUM + 1]bool

var disallowedPortsBitsetInitialized = false

func initDisallowedPortsBitset() {
	for _, port := range disallowedPorts {
		disallowedPortsBitset[port] = true
	}
	disallowedPortsBitsetInitialized = true
}

// IsDisallowedPort returns true if the given destination port number is a value that will be rejected by Fastly.
func IsDisallowedPort(dport uint16) bool {
	if !disallowedPortsBitsetInitialized {
		initDisallowedPortsBitset()
	}
	return dport <= MAX_DISALLOWED_PORT_NUM && disallowedPortsBitset[dport]
}
