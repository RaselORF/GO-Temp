// Issue 89
// Passing tainted data into logrus.Printf can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	log := logrus.New()
	// set the logging level to debug
	log.SetLevel(logrus.DebugLevel)
	// log a formatted message using Printf
	log.Printf("Failed to log %s", username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
