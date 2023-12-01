// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"time"
)

func getSalt() string {
	rand.Seed(time.Now().UnixNano())
	salt := make([]byte, 16)
	rand.Read(salt)
	return hex.EncodeToString(salt)
}

func hashVal(val []byte) []byte {
	salt := getSalt()
	hash := sha256.New()
	hash.Write(val)
	saltBytes := []byte(salt)
	hash.Write(saltBytes)
	hashedBytes := hash.Sum(nil)
	return hashedBytes
}
