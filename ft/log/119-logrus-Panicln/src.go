// Issue 89
// Passing tainted data into logrus.Panicln can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type School struct {
	user User
}
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
func newSchool(user User) School {
	return School{user: user}
}

func (s School) Log() {
	logrus.Panicln(s.user.username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	school := newSchool(user)
	w.Write([]byte("Hello, world!"))
	school.Log()

}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
