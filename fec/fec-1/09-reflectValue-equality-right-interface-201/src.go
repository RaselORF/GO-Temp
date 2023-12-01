// Issue 201
// Comparing reflect.Value directly is almost certainly not correct,
// as it compares the reflect package's internal representation, not the underlying value.

package testdata

import (
	"fmt"
	"reflect"
)

func main() {
	v2 := reflect.ValueOf(30)
	if reflect.ValueOf(10) == v2.Interface() {
		fmt.Print("dkfj")
	}
}

//<<<<<267, 304>>>>>
