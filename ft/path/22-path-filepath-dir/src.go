// Issue 89
// Passing tainted data into filepath.Dir can
// result in Path manipulation attack.

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	dir := filepath.Dir(filePath)
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
