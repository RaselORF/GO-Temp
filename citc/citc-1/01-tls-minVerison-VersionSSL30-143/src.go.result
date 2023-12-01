// Issue 143
// Setting tls.Config.MinVersion to tls.VersionSSL30
// Generate warning

package main

import "crypto/tls"

func main() {
	config := &tls.Config{}
	// OpenRefactory Warning:
	// Usage of insecure protocol version in TLS configuration.
	config.MinVersion = tls.VersionSSL30
}

//<<<<<162, 198>>>>>
