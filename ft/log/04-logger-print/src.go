// Issue 89
// Passing tainted data into logger.Print can
// result in log injection.

package testdata

import (
	"log"
	"net/http"
	"os"
)

func handler(req *http.Request) {
	username := req.URL.Query().Get("username")
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Print(username)
}
