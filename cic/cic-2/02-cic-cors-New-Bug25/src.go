// Setting Access-Control-Allow-Origin to '*'
// will set a loose CORS policy which is security
// sensitive.

package testdata

import (
	"fmt"

	"github.com/rs/cors"
)

const starVal = "*"

func test() {
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{starVal},
		AllowCredentials: true,
		Debug:            false,
	})
	fmt.Print(c)
}

//<<<<<212, 330>>>>>
