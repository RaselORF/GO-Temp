// Issue 126
// Passing tainted data via field of map key

package main

import (
	"net/http"
	"net/url"
	"os/exec"
)

type Box struct {
	data string
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	foo(bar(vals))
}

func bar(v url.Values) string {
	return v.Get("cmd")
}

func get(cn string) map[Box]string {
	return map[Box]string{{cn}: "cmd"}
}

func foo(name string) {
	pm := get(name)
	for bx := range pm {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
