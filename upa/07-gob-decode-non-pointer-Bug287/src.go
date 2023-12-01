// Passing non-pointer arg into gob.Unmarshal
// causes runtime error

package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type Person struct {
}

func main() {
	var buffer bytes.Buffer
	var decodedPerson Person
	decoder := gob.NewDecoder(&buffer)
	err := decoder.Decode(decodedPerson)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return
	}

	// Print the decoded person
	fmt.Println(decodedPerson)
}

//<<<<<262, 291>>>>>
