// Issue 89
// Passing tainted data into Exec can
// result in sql injection.

package testdata

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

func signupHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := sql.Open("postgres", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("INSERT INTO users(username, password) VALUES (%s, %s)", username, password)

	db.Exec(query)
}

func main() {
	http.HandleFunc("/", signupHandler)
	http.ListenAndServe(":8090", nil)
}
