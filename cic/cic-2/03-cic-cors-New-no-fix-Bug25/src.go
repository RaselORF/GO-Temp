// Not setting Access-Control-Allow-Origin to '*'.
// No warning will be given.

package testdata

import (
	"fmt"

	"github.com/rs/cors"
)

func test() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://www.example.com/"},
		AllowCredentials: true,
		Debug:            false,
	})
	fmt.Print(c)
}

//<<<<<161, 298>>>>>
