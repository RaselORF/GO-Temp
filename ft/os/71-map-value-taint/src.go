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
	foo(cmdName)
}

func get(name string) map[string]Box {
	bx := Box{name}
	return map[string]Box{"cmd": bx}
}

func foo(cn string) {
	for _, bx := range get(cn) {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
