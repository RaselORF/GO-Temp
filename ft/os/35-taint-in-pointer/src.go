// Issue 125
// Test for taint propagation via pointer

package main

import (
	"net/http"
	"os/exec"
)

type Msg struct {
	txt string
	n   int
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	msg := &Msg{cmdName, 0}
	foo(msg)
}

func foo(m *Msg) {
	bar(m.txt)
}

func bar(cmdStr string) {
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
