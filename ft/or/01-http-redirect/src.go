// Issue 89
// Writting tainted data into http.Redirect can
// result in Open Redirect attack.

package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("url")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
