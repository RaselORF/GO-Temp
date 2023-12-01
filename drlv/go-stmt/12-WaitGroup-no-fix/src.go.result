// Issue 197
// loop variable is used inside go statement but
// WaitGroup is used to control goroutine.
// Fix should not be generated.

package testdata

import (
	"sync"
)

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			println(i)
			wg.Done()
		}()
		wg.Wait()
	}
}

//<<<<<254, 298>>>>>
