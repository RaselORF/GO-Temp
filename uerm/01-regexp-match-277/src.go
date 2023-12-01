// Issue 277
// Using regexp.Match inside a loop is inefficient

package testdata

import (
	"fmt"
	"regexp"
)

func main() {
	strList := []string{"fooooo", "bAr"}
	for _, str := range strList {
		matched, err := regexp.Match(`foo.*`, []byte(str))
		fmt.Println(matched, err)
	}
}

//<<<<<213, 247>>>>>
