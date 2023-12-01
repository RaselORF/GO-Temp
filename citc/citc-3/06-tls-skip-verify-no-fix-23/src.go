// Issue 23
// Setting InsecureSkipVerify to true but Config is not
// from crypto/tls package.
// No warning will be generated.

package main

type Config struct {
	InsecureSkipVerify bool
}

func main() {
	conf := Config{
		InsecureSkipVerify: true,
	}
	_ = conf
}

//<<<<<216, 254>>>>>
