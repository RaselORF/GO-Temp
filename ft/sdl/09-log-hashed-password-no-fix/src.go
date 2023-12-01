// Issue 263
// Sensitive information has been hashed before logged in plaint text.
// No warning.

package testdata

import (
	"crypto/sha512"
	"log"
	"net/http"
)

func updatePwdHandler(w http.ResponseWriter, r *http.Request) {
	pwd := "MyP@s5w0rd"
	hashed := sha512.Sum512([]byte(pwd))
	log.Printf("Updating with new password %s.\n", hashed)
}

func main() {
	http.HandleFunc("/update", updatePwdHandler)
	http.ListenAndServe(":5000", nil)
}
