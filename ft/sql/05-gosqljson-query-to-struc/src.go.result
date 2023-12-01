// Issue 89
// Passing tainted data into gosqljson.QueryToStructs can
// result in sql injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	"github.com/elgs/gosqljson"
	_ "modernc.org/sqlite"
)

type User struct {
	Id   int    `db:"id"`
	Name string `db:"name"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("sqlite", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	resultStructs := []User{}
	// OpenRefactory Warning:
	// Possible SQL injection!
	// Path:
	//	File: src.go, Line: 27
	//		username := r.FormValue("username")
	//		Variable 'username' is assigned a tainted value from an external source.
	//	File: src.go, Line: 28
	//		password := r.FormValue("password")
	//		Variable 'password' is assigned a tainted value from an external source.
	//	File: src.go, Line: 29
	//		query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	//		Variable 'query' is assigned a tainted value which is passed through a function call.
	//	File: src.go, Line: 32
	//		gosqljson.QueryToStructs(db, &resultStructs, query)
	//		Tainted information is used in a sink.
	gosqljson.QueryToStructs(db, &resultStructs, query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
