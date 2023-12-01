// Issue 126
// Passing tainted data via map

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	comms := vals["cmd"]
	for _, cm := range comms {
		cmd := exec.Command(cm)
		cmd.Run()
	}
}
