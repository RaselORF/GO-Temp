// Issue 198
// cancel function is used in all paths.
// No warning will be given.

package testdata

import (
	"context"
	"log"
	"math/rand"
	"os"
)

func _() {
	_, cancel := context.WithCancel(context.Background())
	switch r := rand.Int() % 5; r {
	case 0:
		panic("boom!")
	case 1:
		log.Fatal()
	case 2:
		cancel()
	case 3:
		print("lets fall")
		fallthrough
	default:
		os.Exit(1)
	}
}

//<<<<<163, 216>>>>>
