// Issue 263
// Sensitive information should not be logged in plaint text.

package testdata

import (
	"log"
	"net/http"
	"os"
)

func updatePwdHandler(w http.ResponseWriter, r *http.Request) {
	logger := log.New(os.Stdout, "updatePwdHandler", log.LstdFlags)
	pwd := "MyP@s5w0rd"
	logger.Println("Updating with new password:", pwd)
}

func main() {
	http.HandleFunc("/update", updatePwdHandler)
	http.ListenAndServe(":80", nil)
}
