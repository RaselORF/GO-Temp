// Issue 126
// Passing tainted data via array

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{}
	var ba [5]Box
	ba[0] = bx
	ba[0].data = cmdName
	foo(ba)
}

func foo(b [5]Box) {
	cmd := exec.Command(b[0].data)
	cmd.Run()
}
