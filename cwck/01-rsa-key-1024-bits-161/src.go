// RSA encryption with key size less
// than 2048
// Generate a warning
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	pvk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}

//<<<<<161, 195>>>>>
