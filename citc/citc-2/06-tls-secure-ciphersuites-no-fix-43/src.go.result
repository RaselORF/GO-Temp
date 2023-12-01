// Issue 143
// No insecure cipher suite in CipherSuites key.
// No warning.

package main

import (
	"crypto/tls"
)

func main() {
	config := &tls.Config{}
	config.CipherSuites = []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}
}

//<<<<<158, 228>>>>>
