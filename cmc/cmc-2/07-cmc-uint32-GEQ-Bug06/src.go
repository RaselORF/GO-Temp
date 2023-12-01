// Value of unsigned integer is non negative.
// So, the expression getUint() >= 0 is always true.
// CMC should generate a warning.

package testdata

func getUint() uint32 {
	return 10
}

func test() bool {
	return getUint() >= 0
}

//<<<<<217, 231>>>>>
