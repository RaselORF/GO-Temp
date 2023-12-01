// Issue 89
// Passing tainted data into SQLiteConn.Exec can
// result in sql injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	ID    int    `db:"id"`
	Name  string `db:"name"`
	Email string `db:"email"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("sqlite3", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	db.Exec(query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
