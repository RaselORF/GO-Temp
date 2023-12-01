// Issue 89
// Passing tainted data into exec.CommandContext.
// Warning should be generated.

package testdata

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	ctx, _ := context.WithTimeout(context.Background(), 3*time.Second)
	cmd := exec.CommandContext(ctx, cmdName)
	op, _ := cmd.Output()
	fmt.Fprintln(w, string(op))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
