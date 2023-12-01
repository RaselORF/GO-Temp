// Issue 195
// Using XSS sanitizer.
// Warning should not be generated.

package main

import (
	"io"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	p := bluemonday.UGCPolicy()
	sanitized := p.Sanitize(param)
	io.WriteString(w, sanitized)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
