// Issue 89
// Passing tainted data into sqlx.tx.Queryx can
// result in sql injection.

package testdata

import (
	"fmt"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := getUserName(r)
	password := getPass(r)
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	connStr := os.Getenv("DbConnStr")
	db, err := sqlx.Connect("mysql", connStr)
	if err != nil {
		panic(err)
	}

	tx, err := db.Beginx()
	if err != nil {
		panic(err)
	}

	rows, err := tx.Queryx(query)
	if err != nil {
		fmt.Print("Error")
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name string
		var email string
		err = rows.Scan(&id, &name, &email)
		if err != nil {
			panic(err)
		}
		fmt.Printf("User %d: %s (%s)\n", id, name, email)
	}
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}

func getUserName(req *http.Request) string {
	return req.URL.Query().Get("username")
}
func getPass(req *http.Request) string {
	return req.URL.Query().Get("password")
}
