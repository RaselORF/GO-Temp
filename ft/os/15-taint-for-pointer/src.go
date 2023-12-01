// Issue 127
// Pass taint through pointer field
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	cmd *exec.Cmd
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	cmd := exec.Command(cmdName)
	cmdBox := &Box{cmd: cmd}
	RunCmd(cmdBox)
}

func RunCmd(b *Box) {
	b.cmd.Run()
}
