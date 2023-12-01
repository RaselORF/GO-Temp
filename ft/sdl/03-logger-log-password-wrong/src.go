// Issue 263
// Sensitive information should not be logged in plaint text.

// In this case, we want to give warning from data leak.
// But there is also a valid path for log injection.
// TODO: In this case prioritize Sdl over Log.

package testdata

import (
	"log"
	"net/http"
	"os"
)

func updatePwdHandler(w http.ResponseWriter, r *http.Request) {
	logger := log.New(os.Stdout, "updatePwdHandler", log.LstdFlags)
	r.ParseForm()
	newPwd := r.Form.Get("password")
	logger.Printf("Updaing new password %s.\n", newPwd)
}

func main() {
	http.HandleFunc("/update", updatePwdHandler)
	http.ListenAndServe(":80", nil)
}
