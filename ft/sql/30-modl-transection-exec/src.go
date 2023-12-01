// Issue 89
// Passing tainted data into db.QueryRowContext can
// result in sql injection.

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/jmoiron/modl"
	_ "github.com/mattn/go-sqlite3"
)

func signupHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	query := fmt.Sprintf("SELECT * FROM users WHERE username = %s", username)

	// Open a SQLite database connection
	connStr := os.Getenv("DbConnStr")
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create a modl database connection
	conn := modl.NewDbMap(db, modl.SqliteDialect{})

	// Start a transaction
	tx, err := conn.Begin()
	if err != nil {
		log.Fatal(err)
	}

	// Execute a SQL statement within the transaction
	_, err = tx.Exec(query)
	if err != nil {
		log.Fatal(err)
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Transaction committed successfully")
}

func main() {
	http.HandleFunc("/", signupHandler)
	http.ListenAndServe(":8090", nil)
}
