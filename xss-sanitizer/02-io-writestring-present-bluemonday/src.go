// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in Cross-Site Scripting.

package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/microcosm-cc/bluemonday"
)

func handler(w http.ResponseWriter, r *http.Request) {
	p := bluemonday.UGCPolicy()
	fmt.Print(p)
	io.WriteString(w, r.URL.Query().Get("param"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
