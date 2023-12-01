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
	m := sha1.New()
	hash := m.Sum(password)
	fmt.Printf("%x\n", hash)
}
