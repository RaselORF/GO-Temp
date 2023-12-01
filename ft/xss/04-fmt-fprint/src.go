// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in exposure to Cross-Site Scripting.

package main

import (
	"fmt"
	"net/http"
)

func server(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, r.URL.Query().Get("param"))
}

func main() {
	http.HandleFunc("/", server)
	http.ListenAndServe(":5000", nil)
}
