// Issue 89
// Passing tainted data into flate.NewReaderDict can
// result in Zip extraction attack.

package main

import (
	"compress/flate"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	dictionary := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit.")
	reader := flate.NewReaderDict(file, dictionary)
	fmt.Print(reader)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
