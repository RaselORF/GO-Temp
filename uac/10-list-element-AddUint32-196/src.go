// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"fmt"
	"sync/atomic"
)

func main() {
	li := []uint32{10, 20}
	li[0] = atomic.AddUint32(&li[0], 30)
	fmt.Println(li)
}

//<<<<<183, 219>>>>>
