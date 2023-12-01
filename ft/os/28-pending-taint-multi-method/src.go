// Issue 125
// Test for pending taint propagation through
// multiple method.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	foo(cmdName)
}

func foo(command string) {
	bar(command)
}

func bar(cmdStr string) {
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
