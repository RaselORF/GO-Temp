// Issue 89
// Passing tainted data into logger.Event.Msgf can
// result in log injection.
package testdata

import (
	"net/http"

	"os"

	"github.com/rs/zerolog"
)

type User struct {
	username string
	password string
}

func newUser(name string, pass string) User {
	return User{
		username: name,
		password: pass,
	}
}

func (u User) Log() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// Log a message with an additional field
	logger.Info().Msgf("Failed to log user %s", u.username)
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	user := newUser(username, password)
	w.Write([]byte("Hello, world!"))
	user.Log()

}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
