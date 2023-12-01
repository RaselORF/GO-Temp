// Issue 125
// Test for pending taint propagation through
// multiple method.

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
	bar()
}

func bar() {
	cmd := exec.Command(cmdName)
	cmd.Run()
}
