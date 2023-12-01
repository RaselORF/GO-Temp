// Value of unsigned integer is non negative.
// So, the expression a >= 0 is always true.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func test() {
	var a uint
	if a >= 0 {
		fmt.Println("value is non-negative")
	}
}

//<<<<<193, 199>>>>>
