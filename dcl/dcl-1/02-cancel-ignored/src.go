// Issue 198
// Returned cancel function should be called, not avoided.
// Warning should be given.

package testdata

import (
	"context"
	"time"
)

var bg = context.Background()

func _() context.Context {
	var ctx context.Context
	makeCtx := func() {
		ctx, _ = context.WithTimeout(bg, 5*time.Second)
	}
	makeCtx()
	return ctx
}

//<<<<<256, 303>>>>>
