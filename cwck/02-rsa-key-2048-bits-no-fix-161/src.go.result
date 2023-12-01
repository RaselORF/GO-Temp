// RSA encryption with key size 2048
// No fix
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func main() {
	pvk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pvk)
}

//<<<<<136, 170>>>>>
