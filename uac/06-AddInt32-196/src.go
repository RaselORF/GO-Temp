// Issue 196
// Direct assignment to atomic value should be avoided.
// Fix will be generated.

package main

import (
	"sync/atomic"
)

func add(x, delta int32) int32 {
	x = atomic.AddInt32(&x, delta)
	return x
}

func main() {
	add(1, 10)
}

//<<<<<171, 201>>>>>
