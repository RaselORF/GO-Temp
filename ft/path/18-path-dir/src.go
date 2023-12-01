// Issue 89
// Passing tainted data into os.Mkdir can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
	"path"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	dir := path.Dir(filePath)
	err := os.Mkdir(dir, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	defer os.RemoveAll(dir)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
