// Issue 198
// cancel function is used in all paths.
// No warning will be given.

package testdata

import (
	"context"
	"fmt"
	"math/rand"
)

func _() {
	_, cancel := context.WithCancel(context.Background())
	if r := rand.Int() % 2; r == 0 {
		cancel()
	} else {
		for {
			fmt.Println("Hello")
		}
	}
}

//<<<<<157, 210>>>>>
