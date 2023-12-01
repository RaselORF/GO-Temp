// Issue 89
// Writting tainted data into Ctx.Send can
// result in Cross-Site Scripting.

package main

import (
	"github.com/gofiber/fiber"
)

func main() {
	app := fiber.New()
	app.Get("/", Handler)
	app.Listen(":3000")
}

func Handler(ctx *fiber.Ctx) {
	fname := ctx.Query("fname")
	ctx.SendFile(fname)
}
