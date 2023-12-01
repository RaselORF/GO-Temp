// Issue 298
// Checking 0 != len(x) is ok
// No fix

package testdata

import "fmt"

func test() {
	var a [10]int
	if 0 != len(a) {
		fmt.Println("Length is 0")
	}
}

//<<<<<119, 130>>>>>
