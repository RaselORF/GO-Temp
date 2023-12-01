// Issue 89
// Passing tainted data into logrus.Fatal can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	w.Write([]byte("Hello, world!"))
	logrus.Fatal(username)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
