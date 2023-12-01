// Setting Access-Control-Allow-Origin to '*'
// will set a loose CORS policy which is security
// sensitive.

package testdata

import (
	"fmt"

	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	a := cors.New(cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept",
	})
	fmt.Print(a)
}

//<<<<<216, 310>>>>>
