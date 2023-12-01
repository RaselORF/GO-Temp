// Issue 89
// Pseudo random number generator should
// be avoided for cryptographic purpose

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"time"
)

func encrypt(text []byte) []byte {
	key := make([]byte, 16)
	rand.Seed(time.Now().UnixNano())
	rand.Read(key)

	block, _ := aes.NewCipher(key)

	nonce := make([]byte, 12)
	rand.Seed(time.Now().UnixNano())
	rand.Read(nonce)

	aesgcm, _ := cipher.NewGCM(block)
	return aesgcm.Seal(nil, nonce, text, nil)
}
