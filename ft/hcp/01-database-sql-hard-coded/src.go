// Issue 89
// Should avoid Passing hard coded password while
// creating db instance

package main

import (
	"database/sql"
	"fmt"
)

func main() {
	connStr := "user=or dbname=pg password=pgpass sslmode=verify-full"
	db, _ := sql.Open("postgres", connStr)
	defer db.Close()
	query := fmt.Sprintf("INSERT INTO users(username, password) VALUES (%s, %s)", "username", "password")
	db.Exec(query)
}
