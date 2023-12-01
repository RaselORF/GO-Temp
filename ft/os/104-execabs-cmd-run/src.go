// Issue 177
// Passing tainted data into execabs.Command.
// Warning should be generated.

package main

import (
	"net/http"

	"golang.org/x/sys/execabs"
)

func handler(w http.ResponseWriter, req *http.Request) {
	cmdName := req.URL.Query().Get("cmd")
	cmd := execabs.Command(cmdName)
	cmd.Run()
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
