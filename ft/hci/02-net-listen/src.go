// Issue 89
// Avoid passing hard coded ip into net.Listen

package main

import (
	"fmt"
	"net"
)

const ip = "127.0.0.1:8080"

func main() {
	listener, err := net.Listen("tcp", ip)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close()
}
