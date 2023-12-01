// Issue 126
// Passing tainted data via array
// element used inside range expression

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
	bx := Box{cmdName}
	var ba [5]Box
	ba[0] = bx
	foo(ba)
}

func foo(b [5]Box) {
	for _, entry := range b {
		cmd := exec.Command(entry.data)
		cmd.Run()
	}
}
