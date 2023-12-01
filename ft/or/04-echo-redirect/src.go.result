// Issue 89
// Writting tainted data into Context.Redirect can
// result in Open Redirect attack.

package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func handler(c echo.Context) error {
	url := c.QueryParam("url")
	return c.Redirect(http.StatusFound, url)
}
func main() {
	e := echo.New()
	e.GET("/redirect", handler)
	e.Logger.Fatal(e.Start(":8080"))
}
