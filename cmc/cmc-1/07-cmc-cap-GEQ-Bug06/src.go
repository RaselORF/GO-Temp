// cap(x) will return non negative value.
// so the expression cap(c) >= 0 is always true.
// CMC should generate a warning.

package testdata

func check(c chan int) bool {
	return cap(c) >= 0
}

//<<<<<182, 193>>>>>
