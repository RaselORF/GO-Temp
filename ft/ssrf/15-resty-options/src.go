// Issue 89
// Passing tainted data into resty.Request.Options can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"

	"github.com/go-resty/resty/v2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	client := resty.New()
	resp, err := client.R().
		EnableTrace().
		Options(urlParam)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprintln(w, resp.String())
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
