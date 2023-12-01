// Shouldn't pass a nil Context, even if a function permits it.
// Pass context.TODO if unsure about which Context to use
package testdata

import (
	"database/sql"
	"fmt"
)

func main() {
	db, err := sql.Open("mysql", "username:password@tcp(localhost:3306)/database_name")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	stmt, err := db.PrepareContext(nil, "SELECT * FROM users")
	if err != nil {
		return
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(nil)
	if err != nil {
		return
	}

	fmt.Print(rows)
}

//<<<<<339, 384>>>>>
