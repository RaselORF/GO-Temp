// Issue 126
// During assignment to field of array element
//		arr[i].x = value
// we don't update the value edge, but pass
// taints from the value to the array field location.
// Test for passing taint through the field of array
// locations from param to caller method.

package main

import (
	"net/http"
	"os/exec"
)

type Box struct {
	data string
}

func HandleReq(req *http.Request) {
	bs := make([]Box, 3)
	foo(req, bs)
	bar(bs)
}

func foo(req *http.Request, boxList []Box) {
	vals := req.URL.Query()
	boxList[0] = Box{vals.Get("cmd")}
}

func bar(bxSl []Box) {
	for _, bx := range bxSl {
		cmd := exec.Command(bx.data)
		cmd.Run()
	}
}
