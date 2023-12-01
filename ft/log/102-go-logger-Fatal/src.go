// Issue 89
// Passing tainted data into logger.Fatal can
// result in log injection.
package main

import (
	"fmt"
	"net/http"

	"os"

	"github.com/apsdehal/go-logger"
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
	w.Write([]byte("Hello, world!"))
	logger, err := logger.New("MyLogger", 1, os.Stdout)
	if err != nil {
		panic(err)
	}
	logStr := fmt.Sprintf("Failed to log in %s", username)
	logger.Fatal(logStr)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
