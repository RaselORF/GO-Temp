// Passing interface arg into json.Unmarshal
// No fix

package testdata

import (
	"encoding/json"
	"fmt"
)

type MyStruct interface {
}

func main() {
	var p MyStruct
	jsonData := []byte(`{"Field": "data"}`)
	err := json.Unmarshal(jsonData, p)
	fmt.Println(err)
}

//<<<<<218, 245>>>>>
