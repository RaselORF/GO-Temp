// Issue 198
// Returned cancel function should be called.
// Warning should be given.

package testdata

import (
	"context"
)

var bg = context.Background()

func _() {
	_, cancel := context.WithCancel(bg)
	if false {
		_ = cancel
	}
}

//<<<<<172, 207>>>>>
