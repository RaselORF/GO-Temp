// Calling recover directly in a defer statement
// has no effect and cannot catch the panic.
// Fix should be generated.

package testdata

func panicRecover() {
	defer recover()
	panic("Lets panic")
}

//<<<<<164, 179>>>>>
