// Issue 89
// Passing tainted data into logger.Panicf can
// result in log injection.
package testdata

import (
	"net/http"

	"os"

	"github.com/apsdehal/go-logger"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	logger, err := logger.New("MyLogger", 1, os.Stdout)
	if err != nil {
		panic(err)
	}
	w.Write([]byte("Hello, world!"))
	logger.Panicf("Failed to log in %s", username)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
