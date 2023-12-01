// Issue 89
// Passing tainted data into logger.DebugF can
// result in log injection.
package main

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
func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	w.Write([]byte("Hello, world!"))
	log, err := logger.New("myLogger", 1, os.Stdout)
	if err != nil {
		panic(err)
	}
	// Log a debug message
	log.DebugF("Failed to log user %s", user.username)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
