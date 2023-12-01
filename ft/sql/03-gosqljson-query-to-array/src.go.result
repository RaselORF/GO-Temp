// Issue 89
// Passing tainted data into gosqljson.QueryToArrays can
// result in log injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/elgs/gosqljson"
	_ "modernc.org/sqlite"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("sqlite", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	// OpenRefactory Warning:
	// Possible SQL injection!
	// Path:
	//	File: src.go, Line: 22
	//		username := r.FormValue("username")
	//		Variable 'username' is assigned a tainted value from an external source.
	//	File: src.go, Line: 23
	//		password := r.FormValue("password")
	//		Variable 'password' is assigned a tainted value from an external source.
	//	File: src.go, Line: 24
	//		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	//		Variable 'query' is assigned a tainted value which is passed through a function call.
	//	File: src.go, Line: 26
	//		gosqljson.QueryToArrays(db, gosqljson.AsIs, query)
	//		Tainted information is used in a sink.
	gosqljson.QueryToArrays(db, gosqljson.AsIs, query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
