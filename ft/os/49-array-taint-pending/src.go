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

var gb []Box

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	gb[0].data = cmdName
	foo()
}

func foo() {
	cmd := exec.Command(gb[0].data)
	cmd.Run()
}
