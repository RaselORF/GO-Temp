// Issue 126
// Passing tainted data via array

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	ss := [2]string{cmdName, "-f"}
	cmd := exec.Command(ss[0])
	cmd.Run()
}
