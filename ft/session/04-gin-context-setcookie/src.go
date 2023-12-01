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
		if sessionID != "" {
			c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
		} else {
			// Session ID has not been set, so generate a new one
			sessionID := "RANDOM_SESSION_ID"
			c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
		}
		// Serve the response
		c.String(200, "Hello, World!")
	})

	r.Run(":8080")
}
