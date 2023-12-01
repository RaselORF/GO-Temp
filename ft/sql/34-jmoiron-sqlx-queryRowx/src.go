// Issue 89
// Passing tainted data into sqlx.qStmt.Exec can
// result in sql injection.

package testdata

import (
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

func handler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sqlx.Connect("mysql", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	db.QueryRowx(query)
}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
