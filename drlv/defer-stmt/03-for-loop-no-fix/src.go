// Issue 197
// loop variable is assigned to a new variable and that
// is used inside defer statement.
// Fix should not be generated.

package testdata

import "fmt"

func _() {
	for i := 0; i < 5; i++ {
		i := i
		defer func() {
			fmt.Println(i)
		}()
	}
}

//<<<<<217, 255>>>>>
