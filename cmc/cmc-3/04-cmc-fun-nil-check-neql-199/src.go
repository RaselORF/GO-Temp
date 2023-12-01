// Issue 199
// comparison of function fn != nil is always true

package main

import "log"

func fn() {}
func main() {
	// non-compliant
	if fn != nil {
		log.Println("can't happen")
	}
}

//<<<<<142, 151>>>>>
