// Issue 126
// Test for passing taint through the field of map
// value locations from param to caller method.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	ss := make(map[string]string)
	bar(req, ss)
	foo(ss)
}

func bar(req *http.Request, mp map[string]string) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	mp["command"] = cmdName
}

func foo(mp map[string]string) {
	for _, val := range mp {
		cmd := exec.Command(val)
		cmd.Run()
	}
}
