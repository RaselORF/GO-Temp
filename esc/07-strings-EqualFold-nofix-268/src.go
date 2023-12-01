// Issue 268
// Not strings.ToLower()
// Nofix

package testdata

import (
	"fmt"
	"strings"
)

func Tolower(str string) string {
	return strings.ToLower(str)
}
func main() {

	if strings.ToLower("str1") == Tolower("STR1") {
		fmt.Print("Matched")
	}
}

//<<<<<180, 222>>>>>
