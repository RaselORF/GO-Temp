// Issue 197
// loop variable is assigned to a new variable and that
// is used inside go statement.
// Fix should not be generated.

package testdata

func _(s []int) {
	for i := 0; i < 10; i++ {
		i := i
		go func() {
			println(i)
		}()
	}
}

//<<<<<208, 239>>>>>
