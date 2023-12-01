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

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{}
	bx.data[0] = cmdName
	foo(&bx)
}

func foo(b *Box) {
	cmd := exec.Command(b.data[0])
	cmd.Run()
}
