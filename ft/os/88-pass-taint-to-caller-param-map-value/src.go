// Issue 126
// During assignment to field of map element
//		entry = mp[key]
//		entry.x = taint
// we don't update the value edge, but pass
// taints from the value to the field location.
// Test for passing taint through the field locations
// of map value from param to caller method.

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

func HandleReq(req *http.Request) {
	bm := make(map[string]Box)
	bar(req, bm)
	foo(bm)
}

func bar(req *http.Request, mp map[string]Box) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	bx := Box{cmdName}
	mp["cmd"] = bx
}

func foo(pm map[string]Box) {
	for _, bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
