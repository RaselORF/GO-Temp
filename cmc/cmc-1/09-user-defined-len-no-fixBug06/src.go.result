// len(s) resolves to a user defined function.
// CMC should not generate any warning.

package testdata

func len(s string) int {
	return -1
}

func check(s string) bool {
	b := 0 <= len(s)
	return b
}

//<<<<<179, 190>>>>>
