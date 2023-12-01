// Issue 89
// Passing tainted data into os.StartProcess.
// Warning should be generated.

package testdata

import (
	"fmt"
	"net/http"
	"os"
	"syscall"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.FormValue("cmd")
	args := []string{req.FormValue("arg0")}

	procAttr := &os.ProcAttr{
		Dir:   "",
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Setpgid: true,
		},
	}
	process, err := os.StartProcess(cmdName, args, procAttr)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Wait for the process to exit
	status, err := process.Wait()
	if err != nil {
		fmt.Println(err.Error())
	}

	if status.Success() {
		fmt.Fprintln(w, "Command completed successfully")
	} else {
		fmt.Fprintf(w, "Command failed with exit code %d", status.ExitCode())
	}
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
