// Issue 89
// Passing tainted data into logrus.logger.Trace can
// result in log injection.
package testdata

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	// Create a new logger
	logger := logrus.New()
	// Set the log level to trace
	logger.SetLevel(logrus.TraceLevel)
	// Log a message at the trace level
	logger.Traceln("failed to login", username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
