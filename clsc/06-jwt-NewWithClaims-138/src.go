// Do not explicitly use the 'none' algorithm.
// This would allow a malicious actor to forge a JWT token that will
// automatically be verified.

package main

import (
	"fmt"

	"github.com/dgrijalva/jwt-go/v4"
)

func main() {
	claims := jwt.StandardClaims{
		Issuer: "test",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	ss, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	fmt.Printf("%v %v\n", ss, err)
}

//<<<<<282, 339>>>>>
