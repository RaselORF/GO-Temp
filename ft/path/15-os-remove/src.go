// Issue 89
// Passing tainted data into os.Remove can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// Remove the file
	err := os.Remove(path)
	if err != nil {
		fmt.Println("Error deleting file:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
