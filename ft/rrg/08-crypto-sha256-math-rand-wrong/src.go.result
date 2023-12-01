// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"
)

func main() {
	rand.Seed(time.Now().UnixNano())
	salt := make([]byte, 16)
	rand.Read(salt)
	data := []byte("Hello, world!")
	hash := sha256.Sum256(data)

	// Print the SHA256 hash as a hexadecimal string
	fmt.Printf("%x\n", hash)
}
