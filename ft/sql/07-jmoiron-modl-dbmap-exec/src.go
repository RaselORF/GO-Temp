// Issue 89
// Passing tainted data into DbMap.Exec can
// result in sql injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/modl"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("mysql", connStr)
	defer db.Close()
	conn := &modl.DbMap{Db: db, Dialect: modl.MySQLDialect{}}

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	conn.Exec(query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
