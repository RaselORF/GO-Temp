// Issue 263
// Sensitive information should not be logged in plaint text.

package testdata

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

func ConnectDb() (*sql.DB, error) {
	logger := logrus.New()

	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASS")
	dbName := os.Getenv("POSTGRES_NAME")

	dbUrl := fmt.Sprintf(os.Getenv("PG_URL"), user, password, dbName)
	var err error
	DB, err := sql.Open("postgres", dbUrl)
	if err != nil {
		failMsg := fmt.Sprintf("Failed to connect to %s", dbUrl)
		logger.Error(failMsg)
		return nil, err
	}
	return DB, nil
}
