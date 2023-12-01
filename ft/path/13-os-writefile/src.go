// Issue 89
// Passing tainted data into os.WriteFile can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data := []byte("This is a new line.\n")
	err := os.WriteFile(path, data, 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
	w.Write(data)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
