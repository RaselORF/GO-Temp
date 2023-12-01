// Issue 89
// Passing tainted data into os.ReadFile can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
