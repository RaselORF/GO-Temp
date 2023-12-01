// Issue 125
// Test for taint inside multi assignment

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	def, cmdName := "pwd", vals.Get("cmd")
	foo(cmdName, def)
}

func foo(cmdName, def string) {
	bar(cmdName, def)
}

func bar(cmdStr, def string) {
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
