// Self assignment in if statement. Warning
// should be inside if block.

package testdata

import "fmt"

func checkDivByThree(a int) {
	if a%3 == 0 {
		fmt.Println("Divided by 3")
	} else if a = a; a%3 == 1 || a%3 == 2 {
		fmt.Println("Not divided by 3")
	}
}

//<<<<<193, 198>>>>>
