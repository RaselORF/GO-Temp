// Issue 142
// Generate pending taint on variadic param,
// resolve during compose.
// Warning should be generated.

package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := getCmdName(vals)
	RunCmd(cmdName)
}

func getCmdName(v url.Values) string {
	return v.Get("cmd")
}

func RunCmd(name ...string) {
	cmd := exec.Command(name[0])
	cmd.Run()
}
