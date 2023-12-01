// Issue 89
// Passing tainted data into logrus.Warningln can
// result in log injection.
package main

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type User struct {
	username string
	password string
}

func newUser(name string, pass string) User {
	return User{
		username: name,
		password: pass,
	}
}

func Log(user User) {
	logrus.Errorln(user.username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	var userArr [10]User
	user := newUser(username, password)
	userArr[0] = user
	w.Write([]byte("Hello, world!"))
	Log(userArr[0])

}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
