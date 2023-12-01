// Both secure and HttpOnly flag is set to false in cookie.
// FIC should generate a fix.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: false,
		Secure:   false,
	})
}

//<<<<<189, 299>>>>>
