// Issue 89
// Passing tainted data into io.CopyBuffer can
// result in Zip extraction attack.

package main

import (
	"bytes"
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file.zip")

	defer file.Close()

	untrustedBuffer := new(bytes.Buffer)

	// Copy the contents of the untrusted file to the buffer
	io.CopyBuffer(untrustedBuffer, file, make([]byte, 1024))
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
