// Issue 89
// Passing tainted data into fasthttp.RequestHeader.SetRequestURI can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/valyala/fasthttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURI(urlParam)
	req.Header.SetMethod("GET")

	// Send HTTP request
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	if err := fasthttp.Do(req, resp); err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	fmt.Printf("Response status: %d\n", resp.StatusCode())
	fmt.Printf("Response body: %s\n", resp.Body())
	fmt.Fprintf(w, "Hello World")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
