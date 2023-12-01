// Issue 89
// Passing tainted data into sqlite.QueryContext can
// result in sql injection.

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/http"
	"os"
)

type User struct {
	username string
	password string
	Name     string
	Age      string
}

type School struct {
	user *User
}

func newSchool(user *User) School {
	return School{
		user: user,
	}
}
func newUser(name string, pass string) *User {
	return &User{
		username: name,
		password: pass,
	}
}

func Query(school School) {
	connStr := os.Getenv("DbConnStr")
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()
	ctx := context.Background()
	params := []driver.NamedValue{}
	query := fmt.Sprintf("SELECT * FROM users WHERE username=%s AND password=%s", school.user.username, school.user.password)
	// Execute the query and process the results
	rows, err := db.QueryContext(ctx, query, params)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var p User
		if err := rows.Scan(&p.Name, &p.Age); err != nil {
			panic(err)
		}
		fmt.Printf("%s is %d years old\n", p.Name, p.Age)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	username := req.URL.Query().Get("username")
	password := req.URL.Query().Get("password")
	school := newSchool(newUser(username, password))
	w.Write([]byte("Hello, world!"))
	Query(school)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
