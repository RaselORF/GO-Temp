// Issue 89
// Passing tainted data into http.Client.Post can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func handler(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")
	client := &http.Client{}
	data := url.Values{}
	data.Set("key", "value")
	req, err := http.NewRequest("POST", urlParam, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(w, "Error creating request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Post(urlParam, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Fprintf(w, "Error fetching URL: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(w, "Error fetching URL: %v", resp.Status)
		return
	}
	fmt.Fprintf(w, "Success")
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
