// Issue 89
// Secure random number generator used.
// No warning will be given.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func encrypt(text []byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)

	block, _ := aes.NewCipher(key)

	nonce := make([]byte, 12)
	rand.Read(nonce)

	aesgcm, _ := cipher.NewGCM(block)
	return aesgcm.Seal(nil, nonce, text, nil)
}
