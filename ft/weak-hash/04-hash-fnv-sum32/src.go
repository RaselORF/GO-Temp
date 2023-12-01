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
	secret := os.Getenv("SECRET")
	h := fnv.New32()
	h.Write([]byte(secret))
	hash := h.Sum32()
	fmt.Printf("%x\n", hash)
}
