// Issue 263
// Sensitive information should not be logged in plaint text.

package testdata

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
)

func GenerateAccessToken(userId int64) string {
	secret := os.Getenv("JWT_SECRET")
	expiryHr, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_IN_HR"))

	claims := jwt.MapClaims{}
	claims["id"] = userId
	claims["expires"] = time.Now().Add(time.Hour * time.Duration(expiryHr)).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokStr, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Print("Failed to create token with secret:", secret)
		return ""
	}
	return tokStr
}
