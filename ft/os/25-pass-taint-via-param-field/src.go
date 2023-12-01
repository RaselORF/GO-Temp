// Issue 125
// Generate pending taint on receiver field, resolve during compose.
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
	box := &Box{}
	vals := req.URL.Query()
	loadCmdInfo(vals, box)
	box.Run()
}

func loadCmdInfo(v url.Values, b *Box) {
	name := v.Get("cmd")
	b.cmd = exec.Command(name)
}
