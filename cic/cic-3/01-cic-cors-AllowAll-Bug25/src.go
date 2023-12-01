// Setting Access-Control-Allow-Origin to '*'
// using AllowAll() is security sensitive.

package testdata

import (
	"net/http"

	"github.com/rs/cors"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{\"hello\": \"world\"}"))
	})

	handler := cors.AllowAll().Handler(mux)
	http.ListenAndServe(":8080", handler)
}

//<<<<<378, 393>>>>>
