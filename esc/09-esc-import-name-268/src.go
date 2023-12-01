// Issue 268
// Inefficient string comparison with strings.ToLower

package testdata

import (
	"fmt"
	STRINGS "strings"
)

func main() {
	if STRINGS.ToLower("str1") == STRINGS.ToLower("STR1") {
		fmt.Print("Matched")
	}
}

//<<<<<142, 192>>>>>
