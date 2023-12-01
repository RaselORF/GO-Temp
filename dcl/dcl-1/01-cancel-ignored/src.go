// Issue 198
// Returned cancel function should be called, not avoided.
// Warning should be given.

package testdata

import "context"

func _() context.Context {
	bg := context.Background()
	ctx, _ := context.WithCancel(bg)
	return ctx
}

//<<<<<193, 225>>>>>
