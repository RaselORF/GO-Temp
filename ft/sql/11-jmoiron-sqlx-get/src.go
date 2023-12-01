// Issue 89
// Passing tainted data into sqlx.qStmt.Get can
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

func handler(w http.ResponseWriter, req *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sqlx.Connect("mysql", connStr)
	defer db.Close()

	username := req.FormValue("username")
	password := req.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	var user User
	db.Get(&user, query)
	fmt.Print(user)
}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
