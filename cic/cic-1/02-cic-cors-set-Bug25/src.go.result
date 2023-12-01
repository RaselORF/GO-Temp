// Setting Access-Control-Allow-Origin to '*'
// will set a loose CORS policy which is security
// sensitive.

package testdata

import "net/http"

const starVal = "*"

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// OpenRefactory Warning:
		// Setting 'Access-Control-Allow-Origin' to '*' will enable
		// a loose CORS policy which is security sensitive.
		w.Header().Set("Access-Control-Allow-Origin", starVal)
		w.Write([]byte("{\"hello\": \"world\"}"))
	})
	http.ListenAndServe(":8080", mux)
}

//<<<<<281, 335>>>>>
