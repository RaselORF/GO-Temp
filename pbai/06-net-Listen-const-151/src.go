// Issue 151
// Binding to all network interfaces

package testdata

import (
	"log"
	"net"
)

const addr = "0.0.0.0:8080"

func main() {
	ln, err := net.Listen("tcp", addr)
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

//<<<<<150, 173>>>>>
