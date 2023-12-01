// Issue 125
// Test for taint propagation in if

package main

import (
	"net/http"
	"os/exec"
)

var cmdName string

func HandleReq(req *http.Request) {
	if req != nil {
		vals := req.URL.Query()
		cmdName = vals.Get("cmd")
	} else {
		cmdName = "pwd"
	}
	foo()
}

func foo() {
	bar(cmdName)
}

func bar(cmdStr string) {
	if len(cmdStr) > 0 {
		cmd := exec.Command(cmdStr)
		cmd.Run()
	}
}
