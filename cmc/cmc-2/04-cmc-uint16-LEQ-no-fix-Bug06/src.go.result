// The expression *a <= 0 is okay.
// CMC should not generate a warning.

package testdata

import (
	"fmt"
)

func check(a *uint16) {
	if *a <= 0 {
		fmt.Println("value is not positive")
	}
}

//<<<<<139, 146>>>>>
