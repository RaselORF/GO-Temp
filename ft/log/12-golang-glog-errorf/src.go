// Issue 89
// Passing tainted data into glob.Errorf can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/golang/glog"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	glog.Errorf("Error occured while logging user %s", username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
