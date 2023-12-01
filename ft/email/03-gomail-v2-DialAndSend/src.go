// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

package main

import (
	"net/http"
	"os"

	"gopkg.in/gomail.v2"
)

func mailHandler(w http.ResponseWriter, r *http.Request) {
	recvMail := r.Form.Get("recv-mail")
	m := gomail.NewMessage()
	m.SetHeader("From", "alex@example.com")
	m.SetHeader("To", recvMail)
	m.SetAddressHeader("Cc", "dan@example.com", "Dan")
	m.SetHeader("Subject", "Hello!")
	m.SetBody("text/html", "Welcome!")

	d := gomail.NewDialer("smtp.example.com", 587, "user", os.Getenv("PWD"))

	if err := d.DialAndSend(m); err != nil {
		panic(err)
	}
}
