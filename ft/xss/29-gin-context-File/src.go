// Issue 89
// Writting tainted data into Ctx.File can
// result in Cross-Site Scripting.

package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	// Define a route that returns a JSON response with indentation
	router.GET("/example", func(c *gin.Context) {
		c.File(c.Param("filename"))
	})

	// Start the server
	router.Run(":8080")
}
