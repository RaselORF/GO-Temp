// Issue 170
// net/http.ListenAndServe method doesn't have
// support for setting timeout
// Using this method can cause the program to hang indefinitely

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

//<<<<<404, 437>>>>>
