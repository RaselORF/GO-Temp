// Issue 89
// Passing tainted data into logrus.DebugLn can
// result in log injection.
package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func getUserName(req *http.Request) string {
	return req.URL.Query().Get("username")
}

func LOG(str string) {
	logrus.Debugln(str)
}
func handler(w http.ResponseWriter, req *http.Request) {
	username := getUserName(req)
	LOG(username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
