// Issue 89
// Passing tainted data into fasthttp.Get can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/valyala/fasthttp"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	resp, err, _ := fasthttp.Get(nil, urlParam) // User input is passed to the `url` variable
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Print(resp)
	fmt.Fprintf(w, "Hello World")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
