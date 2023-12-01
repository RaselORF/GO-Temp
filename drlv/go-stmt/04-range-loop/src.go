// Issue 197
// Using loop variables in go statement. The goroutine
// may observe the wrong value of the variable.
// Fix should be generated.

package testdata

func _(s []int) {
	for x := range s {
		go func() {
			println(x)
		}()
	}
}

//<<<<<203, 234>>>>>
