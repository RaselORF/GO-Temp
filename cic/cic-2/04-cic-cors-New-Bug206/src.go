// Setting Access-Control-Allow-Origin to '*'
// will set a loose CORS policy which is security
// sensitive.
// Warning will be given irrespective of Debug field.

package testdata

import (
	"fmt"

	"github.com/rs/cors"
)

func test() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
		Debug:            true,
	})
	fmt.Print(c)
}

//<<<<<245, 358>>>>>
