// Issue 298
// Checking len(x) != 0 is ok
// No fix

package testdata

import "fmt"

func test() {
	var a [10]int
	if len(a) != 0 {
		fmt.Println("Length is 0")
	}
}

//<<<<<119, 130>>>>>
