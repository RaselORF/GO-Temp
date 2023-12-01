// Issue 268
// Inefficient string comparison with strings.ToLower

package testdata

import (
	"fmt"
	"strings"
)

func main() {
	s1 := "str1"
	s2 := "str2"
	s3 := "str3"
	isEqual := strings.ToLower(s1+s2) == strings.ToLower(s2+s3)
	if isEqual {
		fmt.Print("Matched")
	}
}

//<<<<<184, 232>>>>>
