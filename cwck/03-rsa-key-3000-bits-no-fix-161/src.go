// RSA encryption with key size 3000.
// No fix.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

const bits = 3000

func main() {
	pvk, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}

//<<<<<158, 192>>>>>
