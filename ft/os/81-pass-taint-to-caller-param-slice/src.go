// Issue 126
// During assignment to array element
//		arr[i] = value
// we don't update the value edge, but pass
// taints from the value to the array location.
// Test for passing taint through array locations
// from param to caller method.

package main

import (
	"net/http"
	"os/exec"
)

func HandleReq(req *http.Request) {
	commands := make([]string, 3)
	foo(req, commands)
	bar(commands)
}

func foo(req *http.Request, commands []string) {
	vals := req.URL.Query()
	commands[0] = vals.Get("cmd")
}

func bar(cmdList []string) {
	for _, cmdStr := range cmdList {
		cmd := exec.Command(cmdStr)
		cmd.Run()
	}
}
