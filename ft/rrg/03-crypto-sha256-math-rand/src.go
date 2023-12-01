// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/sha256"
	"math/rand"
	"time"
)

func getSalt() []byte {
	rand.Seed(time.Now().UnixNano())
	salt := make([]byte, 16)
	rand.Read(salt)
	return salt
}

func hashVal(val []byte) []byte {
	salt := getSalt()
	hash := sha256.New()
	hash.Write(val)
	hash.Write(salt)
	hashedBytes := hash.Sum(nil)
	return hashedBytes
}
