// Issue 89
// Passing stack trace into log.
// Warning shouldn't be generated.

package main

import (
	"log"
	"net/http"
	"runtime/debug"
)

func HandleReq(req *http.Request) {
	buf := debug.Stack()
	log.Println(buf)
}
