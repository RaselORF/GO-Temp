// Issue 194
// Hashing sensitive data using weak hashing algorithm
// like md5, sha1 is security sensitive.

package testdata

import (
	"crypto/sha1"
	"fmt"
)

func main() {
	password := []byte("MyP@ssw0rd")
	hashPass(password)
}

func hashPass(pwd []byte) {
	m := sha1.New()
	m.Write(pwd)
	hash := m.Sum(nil)
	fmt.Printf("%x\n", hash)
}
