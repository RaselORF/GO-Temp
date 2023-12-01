// recover is not called directly by a deferred function.
// So, recover has not effect in this case.
// Warning should be generated.

package testdata

import "fmt"

func callRecover() {
	if recover() != nil {
		fmt.Printf("recovered")
	}
}

func bar() {
	defer callRecover() // Okay
	panic("panic")
}

func baz() {
	callRecover()
}

func fun() {
	defer func() {
		baz()
	}()
	panic("Lets panic")
}

//<<<<<192, 201>>>>>
