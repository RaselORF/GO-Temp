// Issue 268
// Inefficient string comparison with strings.ToUpper

package testdata

import (
	"fmt"
	"strings"
)

func main() {
	s1 := "str1"
	isEqual := strings.ToUpper(s1) != strings.ToUpper("str2")
	if isEqual {
		fmt.Print("Matched")
	}
}

//<<<<<156, 202>>>>>
