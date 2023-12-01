// Issue 89
// Passing tainted data into logger.Event.Msg can
// result in log injection.
package testdata

import (
	"net/http"

	"os"

	"github.com/rs/zerolog"
)

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	// Create a new logger instance
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Log a message with an additional field
	logger.Info().Msg(username)
	w.Write([]byte("Hello, world!"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
