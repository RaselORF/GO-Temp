// Issue 89
// Passing tainted data into logrus.Tracef can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type User struct {
	username *string
	password *string
}

type School struct {
	user User
}

func newSchool(user User) School {
	return School{
		user: user,
	}
}
func newUser(name *string, pass *string) User {
	return User{
		username: name,
		password: pass,
	}
}

func Log(school School) {
	logrus.Tracef("Failed to log in %s", *(school.user).username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	username = "abc" + username
	school := newSchool(newUser(&username, &password))
	w.Write([]byte("Hello, world!"))
	Log(school)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
