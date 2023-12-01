// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x := uint32(10)
	y := &x
	z := 10
	z, *y, x = 20, atomic.AddUint32(y, 20), 20
	fmt.Println(*y, z)
}

//<<<<<194, 236>>>>>
