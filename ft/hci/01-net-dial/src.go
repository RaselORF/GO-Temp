// Issue 89
// Avoid passing hard coded ip into net.Dial

package main

import (
	"fmt"
	"net"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:80")
	if err != nil {
		fmt.Println("Error connecting:", err)
		return
	}

	fmt.Println("Connected to", conn.RemoteAddr())
}
