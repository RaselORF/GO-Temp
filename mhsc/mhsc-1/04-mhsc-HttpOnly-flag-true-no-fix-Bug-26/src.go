// HttpOnly flag is set to true in session cookie.
// MHSC shouldn't generate warning.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
	})
}

//<<<<<186, 276>>>>>
