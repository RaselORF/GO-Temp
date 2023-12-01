// Issue 197
// Using loop variables in go statement. The goroutine
// may observe the wrong value of the variable.
// Fix should be generated.

package testdata

import "fmt"

func _() {
	list := []int{1, 2, 3}
	for i, v := range list {
		go func() {
			fmt.Println(i)
			fmt.Println(v)
		}()
	}
}

//<<<<<240, 293>>>>>
