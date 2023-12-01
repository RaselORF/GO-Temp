// Issue 89
// Passing tainted data into os.MkdirAll can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// Create the directory and all its parents if they don't exist
	err := os.MkdirAll(path, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
