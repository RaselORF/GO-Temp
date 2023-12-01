// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in exposure to Cross-Site Scripting.

package main

import (
	"fmt"
	"net/http"
)

func handle(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	fmt.Fprintf(w, "<div>%s</div>", param)
}

func main() {
	http.HandleFunc("/", handle)
	http.ListenAndServe(":8090", nil)
}
