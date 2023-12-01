// Issue 89
// Writting tainted data into Context.Redirect can
// result in Open Redirect attack.

package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func handler(c *gin.Context) {
	url := c.Param("url")
	c.Redirect(http.StatusMovedPermanently, url)
}
func main() {
	router := gin.Default()
	router.GET("/redirect", handler)
	router.Run(":8080")
}
