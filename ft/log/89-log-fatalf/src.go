// Issue 89
// Passing tainted data into log.
// Warning should be generated.

package main

import (
	"log"
	"net/http"
)

func HandleReq(req *http.Request) {
	name := req.URL.Query().Get("username")
	log.Fatalf("user %s logged in.\n", name)
}
