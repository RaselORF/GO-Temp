// Issue 268
// Inefficient string comparison with strings.ToLower

package testdata

import (
	"fmt"
	. "strings"
)

func main() {
	if ToLower("str1") == ToLower("STR1") {
		fmt.Print("Matched")
	}
}

//<<<<<136, 170>>>>>
