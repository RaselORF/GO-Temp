// Issue 89
// Passing tainted data into logger.Print can
// result in log injection.

// Flaky test
// Taint trace message sometimes indicates that taint is coming from username,
// sometimes indicates password as taint source.

package testdata

import (
	"log"
	"net/http"
	"os"
)

func getUserName(req *http.Request) string {
	return req.URL.Query().Get("username")
}
func getPass(req *http.Request) string {
	return req.URL.Query().Get("password")
}
func Handler(req *http.Request) {
	username := getUserName(req)
	password := getPass(req)
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("User %s logged in with password %s", username, password)
}
