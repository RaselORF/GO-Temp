// Issue 194
// Hash generated from weak hashing algorithm hash/crc32.ChecksumIEEE

package testdata

import (
	"fmt"
	"hash/crc32"
)

func main() {
	pwd := []byte("MyP@ssw0rd")
	hash := crc32.ChecksumIEEE(pwd)
	fmt.Printf("%x\n", hash)
}
