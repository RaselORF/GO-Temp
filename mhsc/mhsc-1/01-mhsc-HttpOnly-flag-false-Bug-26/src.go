// HttpOnly flag is set to false in session cookie.
// MHSC should generate a fix.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: false,
	})
}

//<<<<<182, 273>>>>>
