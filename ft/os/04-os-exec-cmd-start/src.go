// Issue 89
// Passing tainted data into exec.Command.
// Warning should be generated.

package testdata

import (
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	cmd := exec.Command(cmdName)
	cmd.Start()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
