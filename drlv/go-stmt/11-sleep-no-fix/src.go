// Issue 197
// loop variable is used inside go statement but
// time.Sleep is used after go statement.
// Fix should not be generated.

package testdata

import "time"

func _(cond bool) {
	for i := 0; i < 5; i++ {
		go func() {
			if cond {
				println("Hello")
			} else {
				println(i)
			}
		}()
		time.Sleep(1 * time.Second)
	}
}

//<<<<<218, 301>>>>>
