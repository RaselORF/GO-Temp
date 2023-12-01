// Issue 89
// Passing tainted data into logrus.Warnf can
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

func getUser(req *http.Request) User {
	return *newUser(req.URL.Query().Get("username"), "pass")
}
func getUserName(req *http.Request) string {
	user := getUser(req)
	return user.username
}
func handler(w http.ResponseWriter, req *http.Request) {
	username := getUserName(req)
	logrus.Warnf("Failed to log in %s", username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
