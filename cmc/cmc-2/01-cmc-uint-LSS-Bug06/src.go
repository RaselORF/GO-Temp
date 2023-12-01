// Value of unsigned integer is non negative.
// So, the expression a < 0 is always false.
// CMC should generate a warning.

package testdata

import (
	"fmt"
)

func main() {
	var a uint
	if a < 0 {
		fmt.Println("a is negativee")
	}
}

//<<<<<193, 198>>>>>
