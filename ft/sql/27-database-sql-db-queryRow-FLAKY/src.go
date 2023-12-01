// Issue 89
// Passing tainted data into db.QueryRow can
// result in sql injection.

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
)

type User struct {
	username string
	password string
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
	db, _ := sql.Open("postgres", connStr)
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM users WHERE username=%s AND password=%s", school.user.username, school.user.password)
	db.QueryRow(query)
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
