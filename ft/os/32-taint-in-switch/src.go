// Issue 125
// Test for taint propagation in switch

package main

import (
	"net/http"
	"os/exec"
)

var cmdName string

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName = vals.Get("cmd")
	foo()
}

func foo() {
	bar(cmdName, "pwd", 1)
}

func bar(c1, c2 string, n int) {
	cmdStr := ""
	switch n {
	case 1:
		cmdStr = c1
	case 2:
		cmdStr = c2
	default:
		cmdStr = "exit"
	}
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
