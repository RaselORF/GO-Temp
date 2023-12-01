// Issue 263
// Sensitive information should not be logged in plaint text.

package testdata

import (
	"log"
	"net/http"
)

func updatePwdHandler(w http.ResponseWriter, r *http.Request) {
	pwd := "MyP@s5w0rd"
	log.Printf("Updating with new password %s.\n", pwd)
}

func main() {
	http.HandleFunc("/update", updatePwdHandler)
	http.ListenAndServe(":80", nil)
}
