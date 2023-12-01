// len(x) will return non negative value.
// so the expression 0 > len(s) is always false.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func check(s []string) {
	if 0 > len(s) {
		fmt.Println("Length is negative")
	}
}

//<<<<<192, 202>>>>>
