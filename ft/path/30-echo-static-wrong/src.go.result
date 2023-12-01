// Issue 89
// Passing tainted data into echo.StaticFS can
// result in Path manipulation attack.

package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func handler(w http.ResponseWriter, r *http.Request) {
	Path := r.URL.Query().Get("path")
	e := echo.New()

	// Serve static files from the "public" directory at the "/static" URL path
	e.Static("/", Path)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
