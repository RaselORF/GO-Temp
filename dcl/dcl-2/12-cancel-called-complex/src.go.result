// Issue 198
// Returned cancel function is called in all paths.
// No warning should be given.

package testdata

import (
	"context"
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
				panic("boom")
			case 1:
				cancel()
			default:
				c := cancel
				defer c()
			}
		}
	}
}

//<<<<<217, 252>>>>>
