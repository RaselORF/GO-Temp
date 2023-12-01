// Issue 89
// Passing tainted data into filepath.WalkDir can
// result in Path manipulation attack.

package main

import (
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	err := filepath.WalkDir(filePath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if !d.IsDir() {
			// perform some action on the file
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
