// Issue 89
// Passing tainted data into HostClient.Post can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/valyala/fasthttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	// Create a new HTTP client
	client := &fasthttp.HostClient{
		Addr: "example.com:80",
	}
	// Create the post arguments
	args := &fasthttp.Args{}
	args.Add("username", "johndoe")
	args.Add("password", "secretpassword")
	resp, _, _ := client.Post(nil, urlParam, args)
	fmt.Print(resp)
	fmt.Fprintf(w, "Hello World")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
