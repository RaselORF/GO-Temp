// len(x) <= 0 expression is ok.
// CMC should not generate a warning.

package testdata

import (
	"fmt"
)

func test() {
	var a [10]int
	if len(a) <= 0 {
		fmt.Println("Length is zero or negative")
	}
}

//<<<<<142, 153>>>>>
