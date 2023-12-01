// Issue 89
// Passing tainted data into ioutil.ReadFile can
// result in Path manipulation attack.

package main

import (
	"io/ioutil"
	"net/http"
)

func getFilePath(req *http.Request) string {
	return req.URL.Query().Get("path")
}
func handler(w http.ResponseWriter, r *http.Request) {
	path := getFilePath(r)
	data, _ := ioutil.ReadFile(path)
	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
