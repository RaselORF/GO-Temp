// Issue 89
// Passing tainted data into bzip2.NewReader can
// result in Zip extraction attack.

package main

import (
	"compress/bzip2"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	reader := bzip2.NewReader(file)
	fmt.Print(reader)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
