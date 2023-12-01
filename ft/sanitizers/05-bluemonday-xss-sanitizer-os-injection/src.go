// Issue 195
// Using XSS sanitizer will not prevent OS command injection.
// Warning should be generated.

package main

import (
	"log"
	"net/http"
	"os/exec"
	"strings"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	reader := strings.NewReader(param)
	p := bluemonday.UGCPolicy()
	sanitized := p.SanitizeReader(reader)
	cmd := exec.Command(sanitized.String())
	if err := cmd.Run(); err != nil {
		log.Println(err)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
