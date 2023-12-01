// Issue 197
// Using loop variables in defer statement.
// deferred function call will observe wrong value
// of the loop variable.
// Fix should be generated.

package testdata

import "fmt"

func _() {
	list := []int{1, 2, 3}
	for _, v := range list {
		defer func() {
			fmt.Println(v)
		}()
	}
}

//<<<<<257, 295>>>>>
