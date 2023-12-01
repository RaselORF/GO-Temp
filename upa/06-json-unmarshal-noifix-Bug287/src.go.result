// Passing pointer arg into json.Unmarshal
// No fix

package testdata

import (
	"encoding/json"
	"fmt"
)

type MyStruct struct {
}

func main() {
	var str *MyStruct
	jsonData := []byte(`{"Field": "data"}`)
	err := json.Unmarshal(jsonData, str)
	fmt.Println(err)
}

//<<<<<216, 245>>>>>
