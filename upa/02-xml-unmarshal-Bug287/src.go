// Passing non-pointer arg into xml.Unmarshal
// causes runtime error

package testdata

import (
	"encoding/xml"
	"fmt"
)

type MyStruct struct {
}

func main() {
	var str MyStruct
	jsonData := []byte(`<MyStruct><Field>field value</Field></MyStruct>`)
	err := xml.Unmarshal(jsonData, str)
	fmt.Println(err)
}

//<<<<<261, 289>>>>>
