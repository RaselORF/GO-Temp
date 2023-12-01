// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in exposure to Cross-Site Scripting.

package main

import (
	"net/http"
)

func server(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<div>" + r.URL.Query().Get("param") + "</div>"))
}

func main() {
	http.HandleFunc("/", server)
	http.ListenAndServe(":5000", nil)
}
