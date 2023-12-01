// Issue 125
// Passing tainted data through field inside return value to caller.
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

func (b Box) Run() {
	b.cmd.Run()
}

func HandleReq(req *http.Request) {
	b := getCmdInfo(req.URL)
	b.Run()
}

func getCmdInfo(url *url.URL) *Box {
	vals := url.Query()
	name := vals.Get("cmd")
	box := &Box{}
	box.cmd = exec.Command(name)
	return box
}
