// Issue 297
// A different context package is imported.
// Add context package with correct named import.

package testdata

import (
	"database/sql"
	"fmt"
	"os"

	context2 "time"

	"golang.org/x/net/context"
)

func main() {
	db, err := sql.Open("mysql", os.Getenv("DB_URL"))
	if err != nil {
		fmt.Println("Error connecting to database:", err)
		return
	}
	defer db.Close()

	context.WithCancel(context.Background())
	_ = context2.Now()

	// Execute a query with the context
	_, err = db.QueryContext(nil, "SELECT * FROM users")
	if err != nil {
		fmt.Println("Error executing query:", err)
		return
	}
}

//<<<<<489, 532>>>>>
