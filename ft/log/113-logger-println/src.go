// Issue 89
// Passing tainted data into logger.Println can
// result in log injection.

package main

import (
	"log"
	"net/http"
	"os"
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
func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Println((*user).username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
