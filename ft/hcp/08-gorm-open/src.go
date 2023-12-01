// Issue 89
// Should avoid Passing hard coded password while
// creating db instance

package main

import (
	"fmt"

	"github.com/jinzhu/gorm"
)

const (
	user     = "dbuser"
	password = "s3cretp4ssword"
)

func main() {
	connStr := fmt.Sprintf("postgres://%s:%s@localhost/pqgotest", user, password)
	db, _ := gorm.Open("postgres", connStr)
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", "username", "password")

	db.Exec(query)
}
