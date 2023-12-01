// cap(s) resolves to a user defined function.
// CMC should not generate any warning.

package testdata

func cap(s []int) int {
	return -1
}

func check(s []int) bool {
	b := 0 <= cap(s)
	return b
}

//<<<<<177, 188>>>>>
