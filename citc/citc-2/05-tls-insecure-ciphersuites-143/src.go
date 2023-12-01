// Issue 143
// Insecure cipher suites in CipherSuites key.
// Generate warning.

package main

import (
	"crypto/tls"
)

func main() {
	config := &tls.Config{}
	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
	}
}

//<<<<<162, 228>>>>>
