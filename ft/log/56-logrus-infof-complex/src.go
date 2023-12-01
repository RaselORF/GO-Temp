// Issue 89
// Passing tainted data into logrus.Infof can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

type User struct {
	username string
	password string
}

func modUser(user User) {
	user.username = "newPass"
}
func newUser(name string, pass string) User {
	return User{
		username: name,
		password: pass,
	}
}
func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	modUser(user)
	logrus.Infof("Failed to log in %s", user.username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
