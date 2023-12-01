// Issue 89
// Passing tainted data into os.Open can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	dir, err := os.Open(path)
	if err != nil {
		fmt.Println("Error opening directory:", err)
		return
	}
	defer dir.Close()
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
