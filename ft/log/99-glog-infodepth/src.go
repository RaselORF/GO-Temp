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

type School struct {
	user User
}

func newSchool(user User) School {
	return School{
		user: user,
	}
}
func newUser(name string, pass string) User {
	return User{
		username: name,
		password: pass,
	}
}

func Log(school School) {
	glog.InfoDepthf(1, school.user.username)
	// Flush the log to ensure all messages are written
	defer glog.Flush()
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	school := newSchool(newUser(username, password))
	w.Write([]byte("Hello, world!"))
	Log(school)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
