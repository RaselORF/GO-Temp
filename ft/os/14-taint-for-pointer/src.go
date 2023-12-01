// Issue 127
// Pass taint through pointer
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
	RunCmd(&cmd)
}

func RunCmd(cp **exec.Cmd) {
	(*cp).Run()
}
