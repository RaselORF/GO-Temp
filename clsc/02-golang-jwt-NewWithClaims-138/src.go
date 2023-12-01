// Do not explicitly use the 'none' algorithm.
// This would allow a malicious actor to forge a JWT token that will
// automatically be verified.

package main

import (
	"fmt"
	"time"

	. "github.com/golang-jwt/jwt/v5"
)

func main() {
	claims := RegisteredClaims{
		// Also fixed dates can be used for the NumericDate
		ExpiresAt: NewNumericDate(time.Unix(1516239022, 0)),
		Issuer:    "test",
	}
	temp := SigningMethodNone
	token := NewWithClaims(temp, claims)
	ss, err := token.SignedString(UnsafeAllowNoneSignatureType)
	fmt.Printf("%v %v\n", ss, err)
}

//<<<<<427, 463>>>>>
