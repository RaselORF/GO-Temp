// cap(x) will return non negative value.
// so the expression cap(x) < 0 is always false.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func test() {
	var a [10]int
	if cap(a) < 0 {
		fmt.Println("Capacity is negative")
	}
}

//<<<<<196, 206>>>>>
