// Issue 125
// Test for taint inside field.
// Here, the field needs to be created dinamically
// in the caller (horizon expansion)

package main

import (
	"net/http"
	"os/exec"
)

type Msg struct {
	comm string
	n    int
}

type Conv struct {
	msg     Msg
	isValid bool
}

type Local struct {
	con Conv
	s   string
}

func HandleReq(req *http.Request) {
	vals := req.URL.Query()
	cmdName := vals.Get("cmd")
	m := Msg{cmdName, 0}
	c := Conv{m, true}
	l := Local{c, "check"}
	foo(l)
}

func foo(loc Local) {
	bar(loc)
}

func bar(loc Local) {
	cmd := exec.Command(loc.con.msg.comm)
	cmd.Run()
}
