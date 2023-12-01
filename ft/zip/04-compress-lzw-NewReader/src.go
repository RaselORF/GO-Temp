// Issue 89
// Passing tainted data into lzw.NewReader can
// result in Zip extraction attack.

package main

import (
	"compress/lzw"
	"fmt"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	reader := lzw.NewReader(file, lzw.LSB, 1000)
	fmt.Print(reader)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
