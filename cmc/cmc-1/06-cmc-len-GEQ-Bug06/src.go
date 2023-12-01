// len(x) will return non negative value.
// so the expression len(a) >= 0 is always true.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func test() {
	var a [10]int
	if len(a) >= 0 {
		fmt.Println("Length of an array found negative")
	}
}

//<<<<<196, 207>>>>>
