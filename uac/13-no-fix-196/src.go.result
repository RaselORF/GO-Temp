// Issue 196
// AddUint32 is not from sync/atomic package.
// No fix will be generated.

package main

import (
	"fmt"
)

type atomic struct{}

func (atomic) AddUint32(addr *uint32, delta uint32) uint32 {
	return *addr + delta
}

func main() {
	x, delta := uint32(10), uint32(20)
	a := atomic{}
	x = a.AddUint32(&x, delta)
	fmt.Println(x)
}

//<<<<<296, 322>>>>>
