// Issue 89
// Passing tainted data into net.Dial can
// result in request forgery.

package main

import (
	"fmt"
	"net"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Fprintf(w, "Error connecting to address: %v", err)
		return
	}
	defer conn.Close()
	fmt.Fprintf(w, "Success")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
