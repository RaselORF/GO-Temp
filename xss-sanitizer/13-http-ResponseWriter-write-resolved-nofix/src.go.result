// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in Cross-Site Scripting.

package main

import (
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	p_bluemonday := bluemonday.UGCPolicy()
	sanitizedData := p_bluemonday.SanitizeBytes([]byte(r.URL.Query().Get("param")))
	w.Write(sanitizedData)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
