// Issue 89
// Passing tainted data into tar.Open can
// result in Zip extraction attack.

package testdata

import (
	"archive/tar"
	"fmt"
	"io"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	// this is a sink
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()

	// this is a sink
	tr := tar.NewReader(file)

	// Extract the files from the archive
	for {
		// this is a passthrough
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			return
		}
		// this is a sink
		targetFile, err := os.Create(header.Name)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer targetFile.Close()

		// this is a sink
		if _, err := io.Copy(targetFile, tr); err != nil {
			fmt.Println(err)
			return
		}
	}

	fmt.Println("Files extracted successfully!")
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
