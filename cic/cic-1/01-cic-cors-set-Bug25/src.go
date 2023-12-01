// Setting Access-Control-Allow-Origin to '*'
// will set a loose CORS policy which is security
// sensitive.

package testdata

import "net/http"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("{\"hello\": \"world\"}"))
	})
	http.ListenAndServe(":8080", mux)
}

//<<<<<259, 309>>>>>
