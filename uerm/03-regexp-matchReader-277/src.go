// Issue 277
// Using regexp.MatchReader inside a loop is inefficient

package testdata

import (
	"fmt"
	"regexp"
	"strings"
)

func main() {
	strList := []string{"fooooo", "bAr"}
	for _, str := range strList {
		r := strings.NewReader(str)
		matched, err := regexp.MatchReader("Hello", r)
		fmt.Println(matched, err)
	}
}

//<<<<<260, 290>>>>>
