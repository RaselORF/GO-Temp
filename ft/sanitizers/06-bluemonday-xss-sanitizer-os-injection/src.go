// Issue 195
// Using XSS sanitizer will not prevent OS command injection.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	p := bluemonday.UGCPolicy()
	sanitized := p.Sanitize(param)
	cmd := exec.Command(sanitized)
	cmd.Run()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
