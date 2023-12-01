// Issue 126
// Test for passing taint through the field of map
// key locations from param to caller method.

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

func HandleReq(req *http.Request) {
	bm := make(map[Box]string)
	bar(req, bm)
	foo(bm)
}

func bar(req *http.Request, mp map[Box]string) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{cmdName}
	mp[bx] = "cmd"
}

func foo(pm map[Box]string) {
	for bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
