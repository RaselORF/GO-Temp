// Issue 216
// Writting tainted data into Ctx.SendString can
// result in XSS

package main

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func handler(ctx *fiber.Ctx) error {
	name := ctx.Query("name")
	return ctx.SendString(fmt.Sprintf("Welcome %s", name))
}

func main() {
	app := fiber.New()
	app.Get("/", handler)
	app.Listen(":3000")
}
