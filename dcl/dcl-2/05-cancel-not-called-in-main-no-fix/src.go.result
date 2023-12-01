// Issue 198
// Returned cancel function is no called in all paths but.
// warning should not be given as this is inside main function.

package testdata

import (
	"context"
	"math/rand"
)

func main() {
	_, c := context.WithCancel(context.Background())
	if rand.Int()%2 == 0 {
		c()
	}
}

//<<<<<206, 254>>>>>
