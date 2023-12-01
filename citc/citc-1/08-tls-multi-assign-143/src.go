// Issue 143
// Setting tls.Config.MinVersion to tls.VersionSSL30
// Generate warning

package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	config := &tls.Config{}
	var a string
	a, config.MinVersion = "dkfd", tls.VersionSSL30
	fmt.Print(a, config)
}

//<<<<<188, 235>>>>>
