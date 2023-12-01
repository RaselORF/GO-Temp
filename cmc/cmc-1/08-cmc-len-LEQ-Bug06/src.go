// len(x) will return non negative value.
// so the expression 0 <= len(s) is always true.
// CMC should generate a warning.

package testdata

func check(s string) bool {
	b := 0 <= len(s)
	return b
}

//<<<<<178, 189>>>>>
