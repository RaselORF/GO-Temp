// Self assignment in for statement. Warning
// should be over for statement.

package testdata

import "fmt"

func main() {
	a := 100
	for i, a := 0, a; i < 10; i++ {
		a += 100
		fmt.Println(a)
	}
}

//<<<<<140, 151>>>>>
