// Issue 89
// Passing tainted data into sqlx.qStmt.Exec can
// result in sql injection.

package main

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
	query := "SELECT * FROM users WHERE name = " + username
	_, err := db.Queryx(query)
	if err != nil {
		fmt.Print(err)
	}
}
func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
