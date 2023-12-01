// Issue 89
// Writting tainted data into Context.Redirect can
// result in Open Redirect attack.

package main

import (
	"github.com/gofiber/fiber"
)

func handler(c *fiber.Ctx) {
	url := c.Query("url")
	c.Redirect(url, fiber.StatusMovedPermanently)
}
func main() {
	app := fiber.New()
	app.Get("/redirect", handler)
	app.Listen(":8080")
}
