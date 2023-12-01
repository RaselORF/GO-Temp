// Issue 125
// Test for taint propagation in loop

package main

import (
	"net/http"
	"os/exec"
)

var cmdName string

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	for {
		cmdName = vals.Get("cmd")
		if len(cmdName) == 0 {
			break
		}
		foo()
	}

}

func foo() {
	bar(cmdName)
}

func bar(cmdStr string) {
	cmd := exec.Command(cmdStr)
	cmd.Run()
}
