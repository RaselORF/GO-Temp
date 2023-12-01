// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/aes"
	"fmt"
	"math/rand"
	"time"
)

func main() {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)
	plaintext := []byte("exampleplaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	// create a buffer for the ciphertext
	ciphertext := make([]byte, len(plaintext))
	// encrypt the plaintext using the CBC cipher and store the result in the ciphertext buffer
	block.Encrypt(ciphertext, plaintext)
	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}
