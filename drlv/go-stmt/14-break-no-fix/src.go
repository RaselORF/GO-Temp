// Issue 197
// loop variable is used inside go statement but
// no fix will be generated for the break statement.
// go statement.

package testdata

func _(s []int, cond bool) {
	for x := range s {
		go func() {
			println(x)
		}()
		if cond {
			break
		}
	}
}

//<<<<<202, 233>>>>>
