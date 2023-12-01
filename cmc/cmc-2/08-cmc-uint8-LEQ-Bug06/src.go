// Value of unsigned integer is non negative.
// So, the expression 0 <= *a is always true.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func check(a *uint8) {
	if 0 <= *a {
		fmt.Println("value is non-negative")
	}
}

//<<<<<191, 198>>>>>
