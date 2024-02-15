package masque

import "time"

// MaxTLSTrials is the number of attempts made when establishing a TLS connection to a proxy.
var MaxTLSTrials int = 10

// MaxTLSDialTimeout is the maximum time duration, in milliseconds, allowed for establishing a TLS connection to the proxy.
// This variable is set to 2000 milliseconds by default.
var MaxTLSDialTimeout time.Duration = time.Duration(2000 * time.Millisecond)
