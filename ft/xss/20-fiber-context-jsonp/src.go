// Issue 89
// Writting tainted data into Ctx.JSONP can
// result in Cross-Site Scripting.

package main

import (
	"github.com/gofiber/fiber"
)

func MyHandler(c *fiber.Ctx) {
	callback := c.Query("callback")
	Data := c.Query("data")
	// Send a JSONP response with the data object
	c.JSONP(Data, callback)
}

func main() {
	app := fiber.New()

	app.Get("/", MyHandler)

	app.Listen(":3000")
}
