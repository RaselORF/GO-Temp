// Issue 198
// cancel function is returned which may be called inside caller.
// No warning will be given to avoid FP.

package testdata

import (
	"context"
)

func _() context.CancelFunc {
	_, c := context.WithCancel(context.Background())
	return c
}

//<<<<<193, 241>>>>>
