// Passing non-pointer arg into json.Unmarshal
// causes runtime error

package testdata

import (
	"encoding/json"
	"fmt"
)

type MyStruct struct {
}

func main() {
	var str MyStruct
	jsonData := []byte(`{"Field": "data"}`)
	err := json.Unmarshal(jsonData, str)
	fmt.Println(err)
}

//<<<<<233, 262>>>>>
