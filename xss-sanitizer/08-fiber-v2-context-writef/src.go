// Issue 89
// Writting tainted data into Ctx.Writef can
// result in Cross-Site Scripting.

package main

import (
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	app.Get("/", handler)

	app.Listen(":3000")
}

func handler(ctx *fiber.Ctx) error {
	name := ctx.Query("name")
	ctx.Writef(name)
	return nil
}
