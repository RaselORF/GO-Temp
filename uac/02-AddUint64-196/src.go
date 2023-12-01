// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x := uint64(10)
	y := &x
	*y = atomic.AddUint64(y, 20)
	fmt.Println(*y)
}

//<<<<<185, 213>>>>>
