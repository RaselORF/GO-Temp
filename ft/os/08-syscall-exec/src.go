// Issue 89
// Passing tainted data into syscall.Exec.
// Warning should be generated.

package testdata

import (
	"net/http"
	"os"
	"syscall"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	args := []string{"-a", "-l", "-h"}
	syscall.Exec(cmdName, args, os.Environ())
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
