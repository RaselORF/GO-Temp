// Issue 89
// Passing tainted data into net.Dialer.Dial can
// result in request forgery.

package main

import (
	"log"
	"net"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	// Create a custom dialer that allows us to set the LocalAddr field
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP("127.0.0.1"),
		},
	}
	// Make a request to a vulnerable web server using user input
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
