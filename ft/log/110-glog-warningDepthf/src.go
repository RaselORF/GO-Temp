// Issue 89
// Passing tainted data into logrus.Infoln can
// result in log injection.
package main

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
)

type User struct {
	username string
	password string
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	user := User{
		username: username,
		password: "nil",
	}
	logStr := fmt.Sprintf("Failed to log user %s", user.username)
	glog.WarningDepthf(1, logStr)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
