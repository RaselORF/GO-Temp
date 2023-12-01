// Issue 89
// Passing tainted data into ioutil.ReadDir can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("Error reading directory:", err)
		return
	}

	for _, file := range files {
		fmt.Println(file.Name())
	}
	w.Write([]byte("Hello world"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
