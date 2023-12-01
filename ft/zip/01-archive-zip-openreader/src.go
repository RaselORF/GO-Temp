// Issue 89
// Passing tainted data into zip.OpenReader can
// result in Zip extraction attack.

package testdata

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	// this is a sink
	zipFile, _ := zip.OpenReader(filePath)
	defer zipFile.Close()
	for _, file := range zipFile.File {
		// pass through
		fileReader, _ := file.Open()
		extractedFile, _ := os.Create(file.Name)
		defer extractedFile.Close()
		// this is a sink
		io.Copy(extractedFile, fileReader)
		fmt.Println("Extracted file:", file.Name)
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
