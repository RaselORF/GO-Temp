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
	foo(map[string]string{"command": cmdName, "args": "-f"})
}

func foo(ss map[string]string) {
	cmd := exec.Command(ss["command"])
	cmd.Run()
}
