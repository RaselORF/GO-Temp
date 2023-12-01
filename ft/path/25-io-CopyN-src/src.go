// Issue 89
// Passing tainted data into io.CopyN can
// result in Path manipulation attack.

package main

import (
	"io"
	"net/http"
	"os"
)

func getSource(r *http.Request) string {
	return r.URL.Query().Get("src-name")
}
func handler(w http.ResponseWriter, r *http.Request) {
	srcFileName := getSource(r)
	src, err := os.Open(srcFileName)
	if err != nil {
		panic(err)
	}
	defer src.Close()

	// Create destination file
	dst, err := os.Create("destination_file.txt")
	if err != nil {
		panic(err)
	}
	defer dst.Close()

	// Copy 10 bytes from source to destination
	n, err := io.CopyN(dst, src, 10)
	if err != nil {
		panic(err)
	}

	// Print number of bytes copied
	println(n)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
