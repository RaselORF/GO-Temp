// Issue 170
// net/http.ListenAndServe method doesn't have
// support for setting timeout
// Using this method can cause the program to hang indefinitely

package testdata

import . "net/http"

func main() {
	mux := NewServeMux()
	mux.HandleFunc("/", func(w ResponseWriter, r *Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write([]byte("{\"hello\": \"world\"}"))
	})
	ListenAndServe(":8080", mux)
}

//<<<<<391, 419>>>>>
