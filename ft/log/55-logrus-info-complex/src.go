// Issue 89
// Passing tainted data into logrus.Info can
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

func modUser(user User) User {
	user.password = "newPass"
	return user
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
	user = modUser(user)
	logrus.Info(user.username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
