// Issue 125
// Passing tainted data as return value to caller.
// Warning should be generated.

package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

func HandleReq(req *http.Request) {
	cmd := getCmdInfo(req.URL)
	cmd.Run()
}

func getCmdInfo(url *url.URL) *exec.Cmd {
	vals := url.Query()
	name := vals.Get("cmd")
	cmd := exec.Command(name)
	return cmd
}
