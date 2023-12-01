// Issue 126
// Passing tainted data via map

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
	ss["args"] = "-f"
	foo(ss)
}

func foo(ss map[string]string) {
	cd := ss["command"]
	cmd := exec.Command(cd)
	cmd.Run()
}
