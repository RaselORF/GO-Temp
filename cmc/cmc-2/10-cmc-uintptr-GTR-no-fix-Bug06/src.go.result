// Value of uintptr is non negative.
// So, the expression u > 0 is okay.
// CMC should not generate a warning.

package main

import (
	"fmt"
	"unsafe"
)

func main() {
	var x struct {
		a int64
	}
	u := unsafe.Alignof(x.a)
	if u > 0 {
		fmt.Println("Alignment is greater than zero")
	}
}

//<<<<<229, 234>>>>>
