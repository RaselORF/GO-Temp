// Issue 89
// Writting tainted data into Ctx.SendStream can
// result in Cross-Site Scripting.

package main

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber"
)

func MyHandler(c *fiber.Ctx) {
	name := c.Query("name")
	html := fmt.Sprintf("<h1>Hello, %s!</h1>", name)
	c.SendStream(strings.NewReader(html))
}
func main() {
	app := fiber.New()

	app.Get("/", MyHandler)

	app.Listen(":3000")
}
