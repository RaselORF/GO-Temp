// Issue 89
// Passing tainted data into syscall.ForkExec.
// Warning should be generated.

package testdata

import (
	"log"
	"net/http"
	"syscall"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.FormValue("cmd")
	args := []string{req.FormValue("arg0")}

	pid, err := syscall.ForkExec(cmdName, args, &syscall.ProcAttr{})
	if err != nil {
		log.Println(err)
	}

	// Wait for the child process to exit
	var status syscall.WaitStatus
	_, err = syscall.Wait4(pid, &status, 0, nil)
	if err != nil {
		log.Println(err)
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
