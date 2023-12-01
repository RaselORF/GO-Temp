// Issue 89
// Passing tainted data into log.panic
// Warning should be generated.

package main

import (
	"log"
	"net/http"
)

func HandleReq(req *http.Request) {
	name := req.URL.Query().Get("username")
	log.Panic("user logged in.", name)
}
