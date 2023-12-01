// Issue 125
// Generate pending taint on global field, resolve during compose.
// Warning should be generated.

package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

type Box struct {
	cmd *exec.Cmd
}

var box Box

func Run() {
	box.cmd.Run()
}

func HandleReq(req *http.Request) {
	cmdName := getCmdName(req)
	RunCmd(cmdName)
}

func getUrlValues(req *http.Request) url.Values {
	return req.URL.Query()
}

func getCmdName(req *http.Request) string {
	vals := getUrlValues(req)
	return vals.Get("cmd")
}

func RunCmd(name string) {
	box.cmd = exec.Command(name)
	Run()
}
