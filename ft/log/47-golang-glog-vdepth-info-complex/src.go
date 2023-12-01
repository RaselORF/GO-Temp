// Issue 89
// Passing tainted data into Verbose.Info can
// result in log injection.
package testdata

import (
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
	glog.VDepth(2, glog.Level(2)).Info(user.username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
