// Issue 198
// cancel function is declared out of function scope.
// No warning will be given.

package testdata

import (
	"context"
	"math/rand"
)

var cancel context.CancelFunc

func _() {
	_, cancel = context.WithCancel(context.Background())
	if r := rand.Int() % 2; r == 0 {
		cancel()
	}
}

//<<<<<194, 246>>>>>
