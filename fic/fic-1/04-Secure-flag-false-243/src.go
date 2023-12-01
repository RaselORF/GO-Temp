// Secure flag is set to false in cookie and
// HttpOnly flag is missing.
// FIC should generate a fix.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  value,
		Secure: false,
	})
}

//<<<<<203, 288>>>>>
