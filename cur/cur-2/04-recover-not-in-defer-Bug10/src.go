// recover is not called directly by a deferred function.
// So, recover has not effect in this case.
// Warning should be generated.

package testdata

import "fmt"

func fun() {
	func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
	panic("Lets panic")
}

//<<<<<200, 209>>>>>
