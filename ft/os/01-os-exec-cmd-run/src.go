// Issue 89
// Passing tainted data into exec.Command.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	cmd := exec.Command(cmdName)
	cmd.Run()
}
