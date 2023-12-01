// Issue 143
// Setting tls.Config.MaxVersion to tls.VersionSSL30
// Generate warning

package main

import "crypto/tls"

func main() {
	config := &tls.Config{}
	config.MaxVersion = tls.VersionSSL30
}

//<<<<<162, 198>>>>>
