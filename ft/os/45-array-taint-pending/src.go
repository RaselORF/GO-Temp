// Issue 126
// Passing tainted data via array

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	ss := [2]string{}
	ss[0] = cmdName
	foo(ss)
}

func foo(cs [2]string) {
	cmd := exec.Command(cs[0])
	cmd.Run()
}
