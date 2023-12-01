// Issue 89
// Passing tainted data into db.QueryContext can
// result in sql injection.

package main

import (
	"context"
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
	query := fmt.Sprintf("SELECT * FROM users WHERE username = %s", username)
	ctx := context.Background()
	rows, _ := db.QueryContext(ctx, query, username)
	defer rows.Close()
	for rows.Next() {
		var id int
		var username string
		var password string
		rows.Scan(&id, &username, &password)
		fmt.Print(id, username, password)
	}
}

func main() {
	http.HandleFunc("/", signupHandler)
	http.ListenAndServe(":8090", nil)
}
