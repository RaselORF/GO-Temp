// Issue 142
// Test for pending taint propagation through
// variadic param of multiple method.

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

func foo(command ...string) {
	bar(command...)
}

func bar(cmdList ...string) {
	for _, cmdStr := range cmdList {
		cmd := exec.Command(cmdStr)
		cmd.Run()
	}
}
