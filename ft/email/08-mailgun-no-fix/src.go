// Issue 266
// No untrusted input is used to construct the email.
// No warning will be given.

package main

import (
	"context"
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
	body := "Hello from Mailgun Go!"
	recipient := "recipient@example.com"

	message := mg.NewMessage(sender, subject, body, recipient)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, id, err := mg.Send(ctx, message)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ID: %s Resp: %s\n", id, resp)
}
