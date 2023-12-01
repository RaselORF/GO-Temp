// Issue 89
// Passing tainted data into os.Chdir can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	err := os.Chdir(path)
	if err != nil {
		fmt.Println("Error changing working directory:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
