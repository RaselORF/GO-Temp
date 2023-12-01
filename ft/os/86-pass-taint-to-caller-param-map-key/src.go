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
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bm := make(map[Box]string)
	bar(cmdName, bm)
	foo(bm)
}

func bar(name string, mp map[Box]string) {
	bx := Box{name}
	mp[bx] = "cmd"
}

func foo(pm map[Box]string) {
	for bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
