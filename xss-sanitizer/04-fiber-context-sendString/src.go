// Issue 216
// Writting tainted data into Ctx.SendString can
// result in XSS

package main

import (
	"github.com/gofiber/fiber"
)

func handler(ctx *fiber.Ctx) {
	name := ctx.Query("name")
	ctx.SendString(name)
}

func main() {
	app := fiber.New()

	app.Get("/", handler)

	app.Listen(":3000")
}
