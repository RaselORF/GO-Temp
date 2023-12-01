// Issue 197
// loop variable is used in a defer statement but
// the defer is follwed by a return statement.
// Fix should not be generated.

package testdata

import "fmt"

func _() {
	for i := 0; i < 5; i++ {
		defer func() {
			fmt.Println(i)
		}()
		return
	}
}

//<<<<<214, 252>>>>>
