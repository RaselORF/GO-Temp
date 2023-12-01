// Issue 199
// comparison of function fn == nil is always false

package main

import "log"

type A struct{}

func (A) Foo() {}

func main() {
	var a A
	// non-compliat
	if a.Foo == nil {
		log.Println("can't happen")
	}
}

//<<<<<174, 186>>>>>
