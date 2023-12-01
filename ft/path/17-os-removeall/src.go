// Issue 89
// Passing tainted data into os.RemoveAll can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// Remove the directory and all its contents
	err := os.RemoveAll(path)
	if err != nil {
		fmt.Println("Error deleting directory:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
