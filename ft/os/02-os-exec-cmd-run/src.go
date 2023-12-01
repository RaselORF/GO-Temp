// Issue 89
// Passing tainted data into exec.Command.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	exec.Command(cmdName).Run()
}
