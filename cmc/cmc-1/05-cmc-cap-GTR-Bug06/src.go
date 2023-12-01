// cap(x) will return non negative value.
// so the expression cap(x) < 0 is always false.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func getSlice() []int {
	return []int{1, 2, 3}
}

func check() {
	if 0 > cap(getSlice()) {
		fmt.Println("Capacity of the slice is negative")
	}
}

//<<<<<232, 251>>>>>
