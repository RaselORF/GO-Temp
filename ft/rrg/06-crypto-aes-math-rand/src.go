// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

func main() {
	password := "myPassword123"
	salt := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(salt)

	saltedPassword := append([]byte(password), salt...)
	hash := sha512.Sum384(saltedPassword)
	fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))
}
