// Issue 89
// Writting tainted data into Ctx.Send can
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
	fname := ctx.Query("fname")
	return ctx.SendFile(fname)
}
