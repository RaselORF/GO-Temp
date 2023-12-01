// Issue 89
// Passing tainted data into zip.NewReader can
// result in Zip extraction attack.

package main

import (
	"archive/zip"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	reader, _ := zip.NewReader(file, 1000)
	// Loop over the files in the ZIP archive and decompress them
	for _, file := range reader.File {
		fmt.Print(file.Name)
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
