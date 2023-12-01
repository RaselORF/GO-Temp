// Missing both secure and HttpOnly in cookie.
// FIC should generate a fix.

package testdata

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:  name,
		Value: value,
	})
}

//<<<<<176, 242>>>>>
