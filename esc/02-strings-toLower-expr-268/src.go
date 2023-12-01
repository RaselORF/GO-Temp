// Issue 268
// Inefficient string comparison with strings.ToLower

package testdata

import (
	"fmt"
	"strings"
)

func main() {
	s1 := "str1"
	isEqual := strings.ToLower(s1) == strings.ToLower("str2")
	if isEqual {
		fmt.Print("Matched")
	}
}

//<<<<<156, 202>>>>>
