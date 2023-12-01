// Issue 89
// Passing tainted data into filepath.Walk can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	// Walk the directory tree and print each file path
	err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			fmt.Println(path)
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
