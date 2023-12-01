// Issue 89
// Writting tainted data into http.SetCookie can
// result in Session Fixation attack.

package main

import (
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ID := r.URL.Query().Get("session_id")
		sessionID := &http.Cookie{
			Name:     "session_id",
			Value:    ID,
			HttpOnly: true,
			Expires:  time.Now().Add(time.Hour * 1),
			Path:     "/",
		}
		http.SetCookie(w, sessionID)
		// Serve the response
		w.Write([]byte("Hello, World!"))
	})
	http.ListenAndServe(":8080", nil)
}
