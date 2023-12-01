// Issue 196
// Result of atomic operation is assigned to same variable
// but in new scope.
// No fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x := uint32(10)
	if x := atomic.AddUint32(&x, 20); x == 30 {
		fmt.Println("x is 30")
	}
}

//<<<<<206, 235>>>>>
