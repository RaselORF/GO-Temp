// Issue 126
// Passing tainted data via map key

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data map[string]string
}

var gb Box

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	gb.data[cmdName] = "name"
	foo()
}

func foo() {
	for key := range gb.data {
		cmd := exec.Command(key)
		cmd.Run()
	}
}
