// Issue 89
// Passing tainted data into sqlx.qStmt.Select can
// result in sql injection.
package testdata

import (
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type User struct {
	ID    int    `db:"id"`
	Name  string `db:"name"`
	Email string `db:"email"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sqlx.Connect("mysql", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	var users []User
	db.Select(&users, query)
	fmt.Printf("Users: %+v\n", users)
}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
