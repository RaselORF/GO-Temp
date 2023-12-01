// Both HttpOnly and Secure flag is set to true in cookie.
// FIC shouldn't generate warning.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   true,
	})
}

//<<<<<193, 301>>>>>
