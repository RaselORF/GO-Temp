// Issue 198
// Returned cancel function should be called.
// Warning should be given.

package testdata

import (
	"context"
	"time"
)

var bg = context.Background()

func _() {
	_, cancel := context.WithTimeout(bg, 5*time.Second)
	if false {
		_ = cancel
	}
}

//<<<<<180, 231>>>>>
