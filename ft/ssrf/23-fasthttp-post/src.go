// Issue 89
// Passing tainted data into fasthttp.Post can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/valyala/fasthttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	// Create the post arguments
	args := &fasthttp.Args{}
	args.Add("username", "johndoe")
	args.Add("password", "secretpassword")

	// Send the HTTP POST request
	responseBody, err, _ := fasthttp.Post(nil, urlParam, args)

	if err != nil {
		fmt.Printf("Error sending request: %s\n", err)
		return
	}

	// Print the response status code and body
	fmt.Printf("Status code: %d\n", responseBody)
	fmt.Fprintf(w, "Hello World")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
