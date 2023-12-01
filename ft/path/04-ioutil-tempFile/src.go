// Issue 89
// Passing tainted data into ioutil.TempFile can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	file, err := ioutil.TempFile(path, "*")
	if err != nil {
		fmt.Println("Error creating temporary file:", err)
		return
	}
	defer file.Close()

	fmt.Println("Temporary file created:", file.Name())
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
