// Issue 196
// Result of atomic operation is assigned to other variable
// No fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x := uint32(10)
	y := atomic.AddUint32(&x, 20)
	fmt.Println(y)
}

//<<<<<183, 212>>>>>
