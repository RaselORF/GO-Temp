// Issue 126
// Passing tainted data via array

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data [2]string
}

var gb Box

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	gb.data[0] = cmdName
	foo()
}

func foo() {
	cmd := exec.Command(gb.data[0])
	cmd.Run()
}
