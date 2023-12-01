// Issue 216
// Writting tainted data into Ctx.Send can
// result in XSS

package main

import (
	"github.com/gofiber/fiber/v2"
)

func handler(ctx *fiber.Ctx) error {
	name := ctx.Query("name")
	return ctx.Send([]byte(name))
}

func main() {
	app := fiber.New()
	app.Get("/", handler)
	app.Listen(":3000")
}
