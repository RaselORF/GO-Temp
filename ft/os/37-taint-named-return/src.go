// Issue 125
// Test for taint inside named return

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	foo(getVals(req))
}

func foo(cmdName, def string) {
	bar(cmdName, def)
}

func bar(cmdStr, def string) {
	cmd := exec.Command(cmdStr)
	cmd.Run()
}

func getVals(req *http.Request) (cmdName string, def string) {
	vals := req.URL.Query()
	def, cmdName = "pwd", vals.Get("cmd")
	return
}
