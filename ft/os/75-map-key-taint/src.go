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

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{cmdName}
	bm := map[Box]string{bx: "cmd"}
	foo(bm)
}

func foo(pm map[Box]string) {
	for bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
