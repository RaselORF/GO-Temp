// Missing HttpOnly in session cookie.
// MHSC should generate a fix.

package testdata

import . "net/http"

func SetInsecureCookie(w ResponseWriter, name, value string) {
	SetCookie(w, &Cookie{
		Name:  name,
		Value: value,
	})
}

//<<<<<174, 230>>>>>
