// Issue 89
// Passing tainted data into gzip.NewReader can
// result in Zip extraction attack.

package main

import (
	"compress/gzip"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	reader, _ := gzip.NewReader(file)
	fmt.Print(reader)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
