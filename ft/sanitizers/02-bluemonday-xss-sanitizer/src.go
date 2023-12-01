// Issue 195
// Using XSS sanitizer.
// Warning should not be generated.

package main

import (
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	p := bluemonday.UGCPolicy()
	paramBytes := []byte(param)
	sanitized := p.SanitizeBytes(paramBytes)
	w.Write(sanitized)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
