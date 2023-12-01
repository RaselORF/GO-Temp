// Issue 198
// Returned cancel function is called.
// No warning should be given.

package testdata

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"time"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		s := bufio.NewScanner(os.Stdin)
		s.Scan()
		cancel()
	}()
	SayHello(ctx, time.Second*5, "Hello")
}

func SayHello(ctx context.Context, d time.Duration, msg string) {
	select {
	case <-ctx.Done():
		fmt.Println(ctx.Err())
	case <-time.After(d):
		fmt.Println(msg)
	}
}

//<<<<<199, 237>>>>>
