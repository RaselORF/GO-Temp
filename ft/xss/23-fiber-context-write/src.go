// Issue 89
// Writting tainted data into Ctx.Write can
// result in Cross-Site Scripting.

package main

import (
	"github.com/gofiber/fiber"
)

func Handler(ctx *fiber.Ctx) {
	name := ctx.Query("name")
	ctx.Write([]byte(name))
}
func main() {
	app := fiber.New()

	app.Get("/", Handler)

	app.Listen(":3000")
}
