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

	// Concatenate the password and salt
	saltedPassword := append([]byte(password), salt...)

	// Compute the SHA512 hash of the salted password
	hash := sha512.Sum512_256(saltedPassword)

	// Print the salt, hash, and salted password as hexadecimal strings
	fmt.Printf("Salt: %s\n", hex.EncodeToString(salt))
	fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))
	fmt.Printf("Salted password: %s\n", hex.EncodeToString(saltedPassword))
}
