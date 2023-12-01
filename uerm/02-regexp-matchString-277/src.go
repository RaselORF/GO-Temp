// Issue 277
// Using regexp.MatchString inside a loop is inefficient

package testdata

import (
	"fmt"
	"regexp"
)

func main() {
	strList := []string{"fooooo", "bAr"}
	for _, str := range strList {
		matched, err := regexp.MatchString(`foo.*`, str)
		fmt.Println(matched, err)
	}
}

//<<<<<219, 251>>>>>
