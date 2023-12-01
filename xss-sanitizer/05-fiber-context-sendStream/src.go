// Issue 216
// Writting tainted data into C.SendStream can
// result in XSS.

package main

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber"
)

func handler(c *fiber.Ctx) {
	name := c.Query("name")
	html := fmt.Sprintf("<h1>Hello, %s!</h1>", name)
	c.SendStream(strings.NewReader(html))
}

func main() {
	app := fiber.New()
	app.Get("/", handler)
	app.Listen(":3000")
}
