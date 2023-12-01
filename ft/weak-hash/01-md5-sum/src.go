// Issue 194
// Hashing sensitive data using weak hashing algorithm
// like md5, sha1 is security sensitive.

package testdata

import (
	"crypto/md5"
	"fmt"
)

func main() {
	password := []byte("MyP@ssw0rd")
	hash := md5.Sum(password)
	fmt.Printf("%x\n", hash)
}
