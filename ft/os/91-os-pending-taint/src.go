// Issue 142
// Generate pending taint on param,
// resolve during compose of variadic function.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	RunCmd(cmdName, 3, 5, 9)
}

func RunCmd(name string, data ...int) {
	cmd := exec.Command(name)
	cmd.Run()
}
