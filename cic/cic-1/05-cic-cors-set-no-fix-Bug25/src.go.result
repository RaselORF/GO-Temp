// Not setting Access-Control-Allow-Origin to '*'.
// No warning will be given.

package testdata

import "net/http"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://www.example.com/")
		w.Write([]byte("{\"hello\": \"world\"}"))
	})
	http.ListenAndServe(":8080", mux)
}

//<<<<<230, 303>>>>>
