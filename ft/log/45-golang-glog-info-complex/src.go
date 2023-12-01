// Issue 89
// Passing tainted data into glog.Info can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/golang/glog"
)

func getUserName(req *http.Request) string {
	return req.URL.Query().Get("username")
}

func LOG(str string) {
	glog.Info(str)
}
func handler(w http.ResponseWriter, req *http.Request) {
	username := getUserName(req)
	LOG(username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
