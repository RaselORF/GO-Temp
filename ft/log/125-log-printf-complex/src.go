// Issue 89
// Passing tainted data into log.
// Warning should be generated.

package main

import (
	"log"
	"net/http"
)

func Log(logStr string) {
	log.Printf(logStr)
}
func HandleReq(req *http.Request) {
	name := req.URL.Query().Get("username")
	Log(name)
}
