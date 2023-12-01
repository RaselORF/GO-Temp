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

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{cmdName}
	bm := make(map[string]Box)
	bm["cmd"] = bx
	foo(bm)
}

func foo(pm map[string]Box) {
	for _, bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
