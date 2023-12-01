// Issue 126
// Passing tainted data via array

package main

import (
	"net/http"
	"os/exec"
)

var gs [2]string

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	gs[0] = cmdName
	foo()
}

func foo() {
	cmd := exec.Command(gs[0])
	cmd.Run()
}
