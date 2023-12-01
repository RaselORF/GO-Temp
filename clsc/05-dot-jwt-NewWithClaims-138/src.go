// Do not explicitly use the 'none' algorithm.
// This would allow a malicious actor to forge a JWT token that will
// automatically be verified.

package main

import (
	"fmt"

	. "github.com/dgrijalva/jwt-go/v4"
)

func main() {
	claims := StandardClaims{
		Issuer: "test",
	}
	token := NewWithClaims(SigningMethodNone, claims)
	ss, err := token.SignedString(UnsafeAllowNoneSignatureType)
	fmt.Printf("%v %v\n", ss, err)
}

//<<<<<280, 329>>>>>
