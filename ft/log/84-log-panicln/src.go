// Issue 89
// Passing tainted data into log.panicln
// Warning should be generated.

package main

import (
	"log"
	"net/http"
)

func HandleReq(req *http.Request) {
	name := req.URL.Query().Get("username")
	log.Panicln("user logged in ", name)
}
