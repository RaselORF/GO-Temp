// Issue 89
// Writting tainted data into Ctx.JSONP can
// result in Cross-Site Scripting.

package main

import "github.com/gofiber/fiber/v2"

func MyHandler(c *fiber.Ctx) error {
	data := c.Query("xml")
	c.XML(data)
	return nil
}

func main() {
	app := fiber.New()

	app.Get("/", MyHandler)

	app.Listen(":3000")
}
