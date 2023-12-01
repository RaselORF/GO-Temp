// Issue 89
// Passing tainted data into ioutil.WriteFile can
// result in Path manipulation attack.

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func getFilePath(req *http.Request) string {
	return req.URL.Query().Get("path")
}
func handler(w http.ResponseWriter, r *http.Request) {
	path := getFilePath(r)
	data := []byte("Hello, world!")
	err := ioutil.WriteFile(path, data, 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
