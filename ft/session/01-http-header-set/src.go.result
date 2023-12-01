// Issue 89
// Writting tainted data into http.Header.Set can
// result in Session Fixation attack.

package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID != "" {
			w.Header().Set("Set-Cookie", "session_id="+sessionID)
		} else {
			sessionID := "RANDOM_SESSION_ID"
			w.Header().Set("Set-Cookie", "session_id="+sessionID)
		}
		w.Write([]byte("Hello, World!"))
	})
	http.ListenAndServe(":8080", nil)
}
