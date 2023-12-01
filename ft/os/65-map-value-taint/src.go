// Issue 126
// Passing tainted data via field of map value

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

var gm map[string]Box

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	gm["cmd"] = Box{cmdName}
	foo()
}

func foo() {
	for _, bx := range gm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
