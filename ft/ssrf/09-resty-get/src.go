// Issue 89
// Passing tainted data into resty.Request.Get can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	restyClient := resty.New()
	response, err := restyClient.R().Get(urlParam)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	fmt.Fprintln(w, response.String())
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
