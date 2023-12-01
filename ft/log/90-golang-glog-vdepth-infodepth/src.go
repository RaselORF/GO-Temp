// Issue 89
// Passing tainted data into Verbose.InfoDepth can
// result in log injection.
package main

import (
	"net/http"

	"github.com/golang/glog"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	glog.V(2).InfoDepthf(1, "User input: %s", username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
