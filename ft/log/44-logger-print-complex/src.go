// Issue 89
// Passing tainted data into logger.Print can
// result in log injection.

package testdata

import (
	"log"
	"net/http"
	"os"
)

func getUserName(req *http.Request) string {
	return req.URL.Query().Get("username")
}

func Handler(req *http.Request) {
	username := getUserName(req)
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Print(username)
}
