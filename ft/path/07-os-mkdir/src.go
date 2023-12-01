// Issue 89
// Passing tainted data into os.Mkdir can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	err := os.Mkdir(path, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}
	defer os.RemoveAll(path)

	fmt.Println("Directory created:", path)
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
