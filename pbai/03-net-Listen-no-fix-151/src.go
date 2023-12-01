// Issue 151
// Binding to single network interface

package testdata

import (
	"log"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", "84.68.10.12:8080")
	if err != nil {
		log.Print(err)
	}
	for {
		_, err := ln.Accept()
		if err != nil {
			log.Print(err)
		}
	}
}

//<<<<<123, 160>>>>>
