// Issue 125
// Generate pending taint on param, resolve during compose.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

func RunCmd(name string) {
	cmd := exec.Command(name)
	cmd.Run()
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	RunCmd(cmdName)
}
