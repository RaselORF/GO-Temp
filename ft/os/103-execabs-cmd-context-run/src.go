// Issue 177
// Passing tainted data into execabs.CommandContext.
// Warning should be generated.

package main

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/sys/execabs"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
	cmd := execabs.CommandContext(ctx, cmdName)
	cmd.Run()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
