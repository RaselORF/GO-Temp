// Issue 126
// Passing tainted data via map value

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	ss := make(map[string]string)
	ss["command"] = cmdName
	cmd := exec.Command(ss["command"])
	cmd.Run()
}
