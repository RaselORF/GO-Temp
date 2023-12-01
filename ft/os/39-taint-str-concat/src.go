// Issue 128
// Test for taint propagation via string concat

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd") + " -f"
	foo(cmdName)
}

func foo(cmd string) {
	bar(cmd)
}

func bar(comm string) {
	cmd := exec.Command(comm)
	cmd.Run()
}
