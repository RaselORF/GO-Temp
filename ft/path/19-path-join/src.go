// Issue 89
// Passing tainted data into os.Create can
// result in Path manipulation attack.

package testdata

import (
	"net/http"
	"os"
	"path"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("path")
	filePath := "/home/abc/Desktop/"

	fullpath := path.Join(filePath, fileName)
	file, _ := os.Create(fullpath)
	defer file.Close()
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
