// Issue 89
// Passing tainted data into logrus.Panicf can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

var school School

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

func Log() {
	logrus.Panicf("Failed to log in %s", school.user.username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	username = "newOne"
	password := req.URL.Query().Get("password")
	username = "abc" + username
	school = newSchool(newUser(username, password))
	w.Write([]byte("Hello, world!"))
	Log()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
