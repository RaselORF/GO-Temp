// Issue 89
// Writting tainted data into http.RedirectHandler.ServeHTTP can
// result in Open Redirect attack.

package main

import (
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("url")
	redirectHandler := http.RedirectHandler(redirectURL, http.StatusFound)
	redirectHandler.ServeHTTP(w, r)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
