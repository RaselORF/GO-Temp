// Issue 89
// Passing tainted data into gorm.Db.Raw can
// result in sql injection.

package testdata

import (
	"fmt"
	"net/http"
	"os"

	"github.com/jinzhu/gorm"
)

type User struct {
	ID    int
	Name  string
	Email string
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	connStr := os.Getenv("DbConnStr")
	db, _ := gorm.Open("mysql", connStr)
	defer db.Close()

	username := r.FormValue("username")
	password := r.FormValue("password")
	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)

	var users []User
	db.Raw(query).Scan(&users)

	// Print the results
	for _, user := range users {
		fmt.Printf("id: %d, name: %s, email: %s\n", user.ID, user.Name, user.Email)
	}
}

func main() {
	http.HandleFunc("/", loginHandler)
	http.ListenAndServe(":8090", nil)
}
