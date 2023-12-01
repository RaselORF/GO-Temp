// Issue 199
// comparison of func type field with nil is ok

package main

import "fmt"

type S struct {
	f func()
}

func temp(s S) {
	if s.f == nil {
		fmt.Print("Func is nil")
	}
}
func main() {
	var s S
	s.f = nil
	temp(s)
}

//<<<<<140, 150>>>>>
