// Issue 89
// Writting stack trace into http response can
// result in Stack Trace Exposure.

package main

import (
	"net/http"
	"runtime/debug"
)

func handlePanic(w http.ResponseWriter, r *http.Request) {
	buf := debug.Stack()
	w.Write(buf)
}
