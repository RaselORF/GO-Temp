// Issue 198
// Returned cancel function should be called in all paths.
// Warning should be given.

package testdata

import (
	"context"
	"fmt"
	"log"
	"math/rand"
)

var bg = context.Background()

func _(cond bool, x int) {
	_, cancel := context.WithCancel(bg)
	if r := rand.Int() % 2; r == 0 {
		cancel()
	} else {
		if cond {
			log.Println("Lets call cancel")
			defer cancel()
		} else {
			switch x % 3 {
			case 0:
				fmt.Println("Forgot to cancel")
			case 1:
				cancel()
			default:
				c := cancel
				defer c()
			}
		}
	}
}

//<<<<<228, 263>>>>>
