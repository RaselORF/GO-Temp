// Issue 89
// Passing tainted data into glog.InfoDepth can
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

func newUser(name string, pass string) *User {
	return &User{
		username: name,
		password: pass,
	}
}

func Log(user *User) {
	glog.V(1).InfoDepth(1, user.username)

	// Flush the log to ensure all messages are written
	defer glog.Flush()
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	Log(user)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
