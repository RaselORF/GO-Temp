// Issue 195
// Using XSS sanitizer.
// Warning should not be generated.

package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	reader := strings.NewReader(param)
	p := bluemonday.UGCPolicy()
	if err := p.SanitizeReaderToWriter(reader, w); err != nil {
		log.Println(err)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
