// Issue 89
// Passing tainted data into http.Client.Get can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, req *http.Request) {
	target := req.FormValue("target")
	url := fmt.Sprintf("https://%s.example.com/data/", target)
	client := &http.Client{}
	resp, err := client.Get(url)
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
