// Issue 197
// Using loop variables in go statement. The goroutine
// may observe the wrong value of the variable.
// Fix should be generated.

package testdata

func _(s []int) {
	for i := 0; i < 10; i++ {
		j := i + 1
		go func() {
			println(i)
			println(j)
		}()
	}
}

//<<<<<223, 268>>>>>
