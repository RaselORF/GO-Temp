// Issue 89
// Passing tainted data into gorm.Db.Exec can
// result in sql injection.

package testdata

import (
	"fmt"
	"net/http"
	"os"

	"github.com/jinzhu/gorm"
)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Open a database connection
	connStr := os.Getenv("DbConnStr")
	db, _ := gorm.Open(connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	db.Exec(query)
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
