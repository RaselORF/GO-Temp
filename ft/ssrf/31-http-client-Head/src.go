// Issue 176
// Passing tainted data into http.Head can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, req *http.Request) {
	target := req.FormValue("targetURL")
	url := fmt.Sprintf("https://%s.example.com/data/", target)
	client := &http.Client{}
	resp, err := client.Head(url)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprint(w, resp)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
