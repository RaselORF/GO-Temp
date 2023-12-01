// Issue 89
// Passing tainted data into logrus.Fatal can
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

func newUser(name string, pass string) *User {
	return &User{
		username: name,
		password: pass,
	}
}

func Log(user *User) {
	logrus.Fatalln((*user).username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	w.Write([]byte("Hello, world!"))
	Log(user)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
