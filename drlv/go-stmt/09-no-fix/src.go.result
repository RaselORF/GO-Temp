// Issue 197
// loop variable is not used inside go statement.
// Fix should not be generated.

package testdata

func _() {
	for i := 0; i < 10; i++ {
		go func(x int) {
			println(x)
		}(i)
	}
}

//<<<<<154, 191>>>>>
