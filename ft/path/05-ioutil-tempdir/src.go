// Issue 89
// Passing tainted data into ioutil.TempDir can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	dir, err := ioutil.TempDir(path, "example")
	if err != nil {
		fmt.Println("Error creating temporary directory:", err)
		return
	}
	defer os.RemoveAll(dir)

	fmt.Println("Temporary directory created:", dir)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
