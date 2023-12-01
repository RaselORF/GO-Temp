// Issue 89
// Passing tainted data into logger.Warning can
// result in log injection.
package testdata

import (
	"net/http"

	"os"

	"github.com/apsdehal/go-logger"
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
	logger, err := logger.New("MyLogger", 1, os.Stdout)
	if err != nil {
		panic(err)
	}
	logger.Warning(user.username)
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
