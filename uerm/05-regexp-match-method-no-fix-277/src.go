// Issue 277
// Using regexp.Match method inside a loop is efficient

package testdata

import (
	"fmt"
	"regexp"
)

func main() {
	strList := []string{"fooooo", "bAr"}
	re, err := regexp.Compile("Hello")
	if err != nil {
		return
	}
	for _, arr := range strList {
		matched := re.Match([]byte(arr))
		fmt.Println(matched)
	}
}

//<<<<<278, 299>>>>>
