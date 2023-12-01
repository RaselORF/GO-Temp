// Issue 89
// Writting tainted data into gin.Context.SetCookie can
// result in Session Fixation attack.

package main

import (
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		sessionID := c.Query("session_id")
		c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
		c.String(200, "Hello, World!")
	})

	r.Run(":8080")
}
