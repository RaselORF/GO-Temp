// Issue 89
// Writting tainted data into Ctx.IndentedJSON can
// result in Cross-Site Scripting.

package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Album struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func handler(c *gin.Context) {
	var newAlbum Album
	if err := c.BindJSON(&newAlbum); err != nil {
		fmt.Print(err)
	}
	c.IndentedJSON(http.StatusCreated, newAlbum)
}
func main() {
	router := gin.Default()

	// Define a route that returns a JSON response with indentation
	router.GET("/example", handler)

	// Start the server
	router.Run(":8080")
}
