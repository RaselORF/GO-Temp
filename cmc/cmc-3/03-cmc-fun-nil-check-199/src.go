// Issue 199
// comparison of function fn == nil is always false

package main

import "log"

func fn() {}
func main() {
	// non-compliant
	if fn == nil {
		log.Println("can't happen")
	}
}

//<<<<<143, 152>>>>>
