// Issue 89
// Writting tainted data into http.ResponseWriter can
// result in exposure to Cross-Site Scripting.

package main

import (
	"net/http"
	"text/template"
)

func handle(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")
	tmpl := template.Must(template.ParseFiles("greetings.html"))
	tmpl.Execute(w, username)
}

func main() {
	http.HandleFunc("/", handle)
	http.ListenAndServe(":8090", nil)
}
