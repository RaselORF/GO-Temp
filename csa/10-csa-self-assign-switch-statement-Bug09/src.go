// Self assignment in type switch statement. Warning
// should be over switch statement.

package testdata

import "fmt"

func checkType(a interface{}) {
	switch a = a; a.(type) {
	case int:
		fmt.Println("a is integer")
	case string:
		fmt.Println("a is string")
	}
}

//<<<<<162, 167>>>>>
