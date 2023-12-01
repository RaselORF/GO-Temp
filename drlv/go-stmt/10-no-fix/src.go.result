// Issue 197
// loop variable is not used inside go statement.
// Fix should not be generated.

package testdata

import "fmt"

func _(s []int) {
	for _, v := range s {
		go func(v int) {
			fmt.Println(v)
		}(v)
	}
}

//<<<<<171, 212>>>>>
