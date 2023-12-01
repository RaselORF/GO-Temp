// Issue 197
// loop variable is used inside go statement.
// Fix should be generated.

package testdata

import (
	"context"
	"net/http"
)

type Batch struct {
	Requests []http.Request
}

func handleBatch(ctx context.Context, batch *Batch) error {
	var chans []chan error
	for _, request := range batch.Requests {
		c := make(chan error)
		go func(c chan error) {
			c <- handle(ctx, request)
		}(c)
		chans = append(chans, c)
	}
	return nil
}

func handle(c context.Context, req http.Request) error {
	println("Handling req...")
	return nil
}

//<<<<<341, 400>>>>>
