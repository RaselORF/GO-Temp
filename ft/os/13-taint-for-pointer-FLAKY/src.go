// Issue 127
// Pass taint through pointer
// Warning should be generated.
// FLAKY test

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	cmd := exec.Command(cmdName)
	if cmd == nil {
		cmd = exec.Command("default")
	}
	cmdPtr := &cmd
	actualCmd := **cmdPtr
	actualCmd.Run()
}
