// Issue 126
// Passing tainted data via field of map key

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

var gm map[Box]string

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{cmdName}
	gm[bx] = "cmd"
	foo()
}

func foo() {
	for bx := range gm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
