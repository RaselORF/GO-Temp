// Issue 89
// Passing tainted data into db.Exec can
// result in sql injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

func signupHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("postgres", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("INSERT INTO users(username, password) VALUES (%s, %s)", username, password)
	// OpenRefactory Warning:
	// Possible SQL injection!
	// Path:
	//	File: src.go, Line: 19
	//		username := r.FormValue("username")
	//		Variable 'username' is assigned a tainted value from an external source.
	//	File: src.go, Line: 20
	//		password := r.FormValue("password")
	//		Variable 'password' is assigned a tainted value from an external source.
	//	File: src.go, Line: 21
	//		query := fmt.Sprintf("INSERT INTO users(username, password) VALUES (%s, %s)", username, password)
	//		Variable 'query' is assigned a tainted value which is passed through a function call.
	//	File: src.go, Line: 22
	//		db.Exec(query)
	//		Tainted information is used in a sink.
	db.Exec(query)
}

func main() {
	http.HandleFunc("/", signupHandler)
	http.ListenAndServe(":8090", nil)
}
