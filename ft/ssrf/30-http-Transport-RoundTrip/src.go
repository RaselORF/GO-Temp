// Issue 176
// Passing tainted data into http.Transport.RoundTrip can
// result in request forgery.

package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("targetURL")
	targetUrl := fmt.Sprintf("https://%s.example.com/data/", target)
	proxyURL, err := url.Parse("http://localhost:8888")
	if err != nil {
		panic(err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		panic(err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
