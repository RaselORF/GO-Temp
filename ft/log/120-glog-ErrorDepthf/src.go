// Issue 89
// Passing tainted data into glog.ErrorDepthf can
// result in log injection.
package main

import (
	"net/http"

	"github.com/golang/glog"
)

type User struct {
	username string
	password string
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	user := User{
		username: username,
		password: "nil",
	}
	w.Write([]byte("Hello, world!"))
	glog.ErrorDepthf(1, "Failed to log user %s", user.username)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
