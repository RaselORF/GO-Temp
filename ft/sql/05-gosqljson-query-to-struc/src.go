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
	gosqljson.QueryToStructs(db, &resultStructs, query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
