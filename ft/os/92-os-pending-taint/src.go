// Issue 142
// Generate pending taint on param,
// resolve during compose of variadic function.
// Warning should be generated.

package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := getCmdName(vals, "x", "y", "z")
	RunCmd(cmdName, true)
}

func getCmdName(v url.Values, a ...string) string {
	return v.Get("cmd")
}

func RunCmd(name string, b ...bool) {
	cmd := exec.Command(name)
	cmd.Run()
}
