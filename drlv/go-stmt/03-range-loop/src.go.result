// Issue 197
// Using loop variables in go statement. The goroutine
// may observe the wrong value of the variable.
// Fix should be generated.

package testdata

import (
	"fmt"
)

func _(list1 []int) {
	list2 := []int{1, 2, 3}
	for _, v := range list1 {
		for idx, v2 := range list2 {
			fmt.Println(idx)
			go func() {
				fmt.Println(v2)
				fmt.Println(v)
			}()
		}
	}
}

//<<<<<310, 367>>>>>
