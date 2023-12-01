// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

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
	user := r.URL.Query().Get("name")

	sender := "sender@example.com"
	subject := "Fancy subject!"
	body := "Welcome %s, Hello from Mailgun Go!"
	recipient := "recipient@example.com"

	msgBody := fmt.Sprintf(body, user)
	message := mg.NewMessage(sender, subject, msgBody, recipient)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	resp, id, err := mg.Send(ctx, message)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ID: %s Resp: %s\n", id, resp)
}
