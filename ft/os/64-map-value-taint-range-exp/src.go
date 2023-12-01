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
	ss := map[string]string{"command": cmdName, "args": "-f"}
	for _, val := range ss {
		cmd := exec.Command(val)
		cmd.Run()
	}
}
