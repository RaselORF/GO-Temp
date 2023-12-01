// Both HttpOnly and Secure flag is set from parameter.
// FIC shouldn't generate warning.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string, httpOnly, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: httpOnly,
		Secure:   secure,
	})
}

//<<<<<213, 327>>>>>
