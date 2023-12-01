// Issue 89
// Passing tainted data into logger.Panicf can
// result in log injection.
package testdata

import (
	"net/http"

	"os"

	"github.com/apsdehal/go-logger"
)

type ICR struct {
	users [10]User
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

func Log(icr ICR) {
	logger, err := logger.New("MyLogger", 1, os.Stdout)
	if err != nil {
		panic(err)
	}
	logger.Panicf("Failed to log in %s", icr.users[0].username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	var icr ICR
	user := newUser(username, password)
	icr.users[0] = user
	w.Write([]byte("Hello, world!"))
	Log(icr)

}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
