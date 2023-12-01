// Issue 198
// Returned cancel function is called.
// No warning should be given.

package testdata

import (
	"context"
	"time"
)

var bg = context.Background()

func _(condition bool) {
	_, cancel := context.WithTimeout(bg, 5*time.Second)
	if condition {
		foo := cancel
		foo()
	} else {
		defer cancel()
	}
}

//<<<<<190, 241>>>>>
