// Value of unsigned integer is non negative.
// So, the expression 0 > a is always false.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func check(a uint64) {
	if 0 > a {
		fmt.Println("value is negative")
	}
}

//<<<<<190, 195>>>>>
