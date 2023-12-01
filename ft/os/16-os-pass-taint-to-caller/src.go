// Issue 125
// Passing tainted data as return value to caller function.
// Warning should be generated.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	cmdName := GetCmdName(req)
	cmd := exec.Command(cmdName)
	cmd.Run()
}

func GetCmdName(req *http.Request) string {
	vals := req.URL.Query()
	return vals.Get("cmd")
}
