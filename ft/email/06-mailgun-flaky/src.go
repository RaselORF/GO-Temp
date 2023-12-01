// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mailgun/mailgun-go/v4"
)

var domain string = os.Getenv("DOMAIN")
var privateAPIKey string = os.Getenv("KEY")

func mailHandler(w http.ResponseWriter, r *http.Request) {
	mg := mailgun.NewMailgun(domain, privateAPIKey)

	sender := "sender@example.com"
	subject := "Fancy subject!"
	body := ""
	recipient := "recipient@example.com"

	message := mg.NewMessage(sender, subject, body, recipient)
	message.SetTemplate("passwordReset")
	link, err := getLink(r)
	if err != nil {
		log.Fatal(err)
	}
	err = message.AddTemplateVariable("passwordResetLink", link)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, id, err := mg.Send(ctx, message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ID: %s Resp: %s\n", id, resp)
}

func getLink(r *http.Request) (string, error) {
	token := make([]byte, 32) // Generate a 32-byte random token
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	resetToken := fmt.Sprintf("%x", token)
	link := "%s/reset-password?token=%s"
	return fmt.Sprintf(link, r.Host, resetToken), nil
}
