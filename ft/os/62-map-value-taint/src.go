// Issue 126
// Passing tainted data via map value

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
	gb.data["name"] = cmdName
	foo()
}

func foo() {
	cmd := exec.Command(gb.data["name"])
	cmd.Run()
}
