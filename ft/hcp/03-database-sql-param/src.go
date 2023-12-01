// Issue 89
// Should avoid Passing hard coded password while
// creating db instance

package main

import (
	"database/sql"
	"fmt"
)

func Query(user, password string) {
	connStr := fmt.Sprintf("postgres://%s:%s@localhost/pqgotest", user, password)
	db, _ := sql.Open("postgres", connStr)
	defer db.Close()

	query := fmt.Sprintf("INSERT INTO users(username, password) VALUES (%s, %s)", "username", "password")
	db.Exec(query)
}

func main() {
	Query("user", "pass")
}
