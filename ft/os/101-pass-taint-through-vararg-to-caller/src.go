// Issue 142
// Test for pending taint propagation through
// variadic param of multiple method.

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	cmds []string
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	commands := []string{vals.Get("cmd")}
	box := &Box{}
	foo(box, commands...)
	bar(box)
}

func foo(b *Box, commands ...string) {
	b.cmds = commands
}

func bar(b *Box) {
	for _, cmdStr := range b.cmds {
		cmd := exec.Command(cmdStr)
		cmd.Run()
	}
}
