// Issue 170
// server is properly configured with timeout.
// No fix will be generated.

package testdata

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func slowHandler(w http.ResponseWriter, req *http.Request) {
	time.Sleep(5 * time.Second)
	io.WriteString(w, "Me too slow!\n")
}

func main() {
	srv := http.Server{
		Addr:         ":8888",
		WriteTimeout: 5 * time.Second,
		Handler:      http.TimeoutHandler(http.HandlerFunc(slowHandler), 1*time.Second, "Timeout!\n"),
	}

	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("Server failed: %s\n", err)
	}
}

//<<<<<488, 508>>>>>
