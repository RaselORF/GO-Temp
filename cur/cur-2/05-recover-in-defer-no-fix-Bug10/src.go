// recover is called directly by a deferred function.
// No warning.

package testdata

import "fmt"

func fun() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
	panic("Lets panic")
}

//<<<<<141, 150>>>>>
