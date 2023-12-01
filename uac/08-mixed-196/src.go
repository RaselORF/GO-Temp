// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	x, y := uint32(10), int64(100)
	x, y = atomic.AddUint32(&x, 20), atomic.AddInt64(&y, 200)
	fmt.Println(x, y)
}

//<<<<<191, 248>>>>>
