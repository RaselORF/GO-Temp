// Issue 143
// Setting tls.Config.MinVersion to tls.VersionSSL30.
// Generate warning

package main

import "crypto/tls"

func main() {
	config := &tls.Config{
		MaxVersion: tls.VersionTLS10,
	}
	_ = config
}

//<<<<<149, 195>>>>>
