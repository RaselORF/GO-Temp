// Issue 126
// Test for passing taint through the field of map
// key locations from param to caller method.

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
	mp[cmdName] = "command"
}

func foo(mp map[string]string) {
	for key := range mp {
		cmd := exec.Command(key)
		cmd.Run()
	}
}
