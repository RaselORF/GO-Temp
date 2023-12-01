// Issue 201
// Comparing reflect.Value directly is almost certainly not correct,
// as it compares the reflect package's internal representation, not the underlying value.

package testdata

import (
	"fmt"
	"reflect"
)

func main() {
	if reflect.ValueOf(10) == reflect.ValueOf(30) {
		fmt.Print("dkfj")
	}
}

//<<<<<240, 282>>>>>
