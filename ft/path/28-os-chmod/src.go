// Issue 89
// Passing tainted data into os.Chown can
// result in Path manipulation attack.

package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// Change the ownership of the file
	err := os.Chmod(path, 0444)
	if err != nil {
		fmt.Println("Error changing mode:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
