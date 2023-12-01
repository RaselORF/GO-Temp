// Issue 126
// Passing tainted data via array
// element used inside range expression

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
	for _, cname := range cs {
		cmd := exec.Command(cname)
		cmd.Run()
	}
}
