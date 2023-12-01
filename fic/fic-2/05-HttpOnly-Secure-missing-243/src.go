// Secure flag is missing session.Options.
// FIC-2 shouldn generate a fix.

package testdata

import (
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

func MyHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	a := sessions.Options{
		Path:   "/",
		MaxAge: 3600,
	}
	session.Options = &a
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//<<<<<330, 386>>>>>
