// Issue 142
// Test for pending taint propagation through
// variadic param of multiple method.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	commands := make([]string, 3)
	foo(req, commands...)
	bar(commands...)
}

func foo(req *http.Request, commands ...string) {
	vals := req.URL.Query()
	commands[0] = vals.Get("cmd")
}

func bar(cmdList ...string) {
	for _, cmdStr := range cmdList {
		cmd := exec.Command(cmdStr)
		cmd.Run()
	}
}
