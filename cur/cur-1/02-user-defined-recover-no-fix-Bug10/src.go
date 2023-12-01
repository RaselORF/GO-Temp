// Calling user defined recover from defer statement.
// No warning.

package testdata

func recover() {}

func panicRecover() {
	defer recover()
	panic("Lets panic")
}

//<<<<<130, 145>>>>>
