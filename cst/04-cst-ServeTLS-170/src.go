// Issue 170
// net/http.ServeTLS method doesn't have
// support for setting timeout
// Using this method can cause the program to hang indefinitely

package testdata

import (
	"fmt"
	"log"
	"net"
	"net/http"
)

func main() {
	listener, _ := net.Listen("tcp", ":8080")
	handler := func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, HTTPS world!")
	}
	// Start the HTTPS server with a TLS certificate.
	err := http.ServeTLS(listener, http.HandlerFunc(handler), "cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
}

//<<<<<431, 504>>>>>
