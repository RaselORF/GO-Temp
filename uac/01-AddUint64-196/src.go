// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x := uint64(1)
	x = atomic.AddUint64(&x, 3)
	fmt.Println(x)
}

//<<<<<175, 202>>>>>
