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
	var ss [5][2]string
	ss[0][0] = cmdName
	ss[1][0] = "-f"
	foo(ss)
}

func foo(cs [5][2]string) {
	cmd := exec.Command(cs[0][0])
	cmd.Run()
}
