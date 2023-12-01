// Issue 89
// Writting stack trace into http response can
// result in Stack Trace Exposure.

package main

import (
	"net/http"
	"runtime"
)

func handlePanic(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 2<<16)
	buf = buf[:runtime.Stack(buf, true)]
	w.Write(buf)
}
