// Issue 143
// Insecure cipher suites in CipherSuites key.
// Generate warning.

package main

import (
	. "crypto/tls"
	"fmt"
)

func main() {
	config := &Config{
		CipherSuites: []uint16{
			TLS_RSA_WITH_RC4_128_SHA,
		},
	}
	fmt.Print(config)
}

//<<<<<157, 227>>>>>
