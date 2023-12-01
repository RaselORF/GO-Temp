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
	cert := os.Getenv("CERT")
	h := fnv.New32a()
	h.Write([]byte("Not sensitive value"))
	h.Write([]byte(cert))
	hash := h.Sum(nil)
	fmt.Printf("%x\n", hash)
}
