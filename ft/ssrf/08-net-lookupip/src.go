// Issue 89
// Passing tainted data into net.LookupIP can
// result in request forgery.

package main

import (
	"fmt"
	"net"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	// Use net.LookupIP to resolve the host name specified in the url parameter
	ips, err := net.LookupIP(urlParam)
	if err != nil {
		fmt.Fprintf(w, "Error resolving IP address: %v", err)
		return
	}
	// Print the IP address(es) returned by net.LookupIP
	fmt.Fprintf(w, "IP addresses: %v", ips)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
