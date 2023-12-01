// Issue 89
// Passing tainted data into os.Chown can
// result in Path manipulation attack.

package testdata

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// Get the user and group IDs for the new owner
	uid := 1001
	gid := 1001
	// Change the ownership of the file
	err := os.Chown(path, uid, gid)
	if err != nil {
		fmt.Println("Error changing ownership:", err)
		return
	}
	w.Write([]byte("Hello"))
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
