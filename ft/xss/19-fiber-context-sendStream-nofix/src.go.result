// Issue 89
// Writting tainted data into Ctx.SendStream can
// result in Cross-Site Scripting.

package testdata

import (
	"fmt"
	"html"
	"strings"

	"github.com/gofiber/fiber"
)

func MyHandler(c *fiber.Ctx) {
	name := c.Query("name")
	sanitized := html.EscapeString(name)
	html := fmt.Sprintf("<h1>Hello, %s!</h1>", sanitized)
	c.SendStream(strings.NewReader(html))
}

func main() {
	app := fiber.New()

	app.Get("/", MyHandler)

	app.Listen(":3000")
}
