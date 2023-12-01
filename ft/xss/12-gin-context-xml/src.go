// Issue 89
// Writting tainted data into Ctx.XML can
// result in Cross-Site Scripting.

package main

import (
	"encoding/xml"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type User struct {
	XMLName xml.Name `xml:"user"`
	Name    string   `xml:"name"`
	Email   string   `xml:"email"`
}

func main() {
	router := gin.Default()

	// Define a route that returns a JSON response with indentation
	router.GET("/example", func(c *gin.Context) {
		var newUser User
		if err := c.BindJSON(&newUser); err != nil {
			fmt.Print(err)
		}
		c.XML(http.StatusCreated, newUser)
	})

	// Start the server
	router.Run(":8080")
}
