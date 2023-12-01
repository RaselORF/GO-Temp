// Issue 89
// Passing tainted data into yaml.Unmarshal can
// result in Deserialization attack.

package testdata

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"
)

type Person struct {
	Name string `yaml:"name"`
	Age  int    `yaml:"age"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	var person Person
	err = yaml.Unmarshal(file, &person)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Name: %s, Age: %d\n", person.Name, person.Age)

	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
