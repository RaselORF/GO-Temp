// Issue 194
// Hashing sensitive data using weak hashing algorithm
// like fnv-1 or fnv-2 is security sensitive.

package testdata

import (
	"fmt"
	"hash/fnv"
	"os"
)

func main() {
	pwd := []byte(getPass())
	h := fnv.New32()
	hash := h.Sum(pwd)
	fmt.Printf("%x\n", hash)
}

func getPass() string {
	return os.Getenv("PASSWORD")
}
