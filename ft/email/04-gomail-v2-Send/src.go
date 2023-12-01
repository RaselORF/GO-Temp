// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

package main

import (
	"fmt"
	"net/http"
	"os"

	"gopkg.in/gomail.v2"
)

func mailHandler(w http.ResponseWriter, r *http.Request) {
	recvName := r.Form.Get("recv-name")
	m := gomail.NewMessage()
	m.SetHeader("From", "alex@example.com")
	m.SetHeader("To", "bob@example.com")
	m.SetHeader("Subject", "Hello!")

	body := fmt.Sprintf("Welcome %s!", recvName)
	m.SetBody("text/html", body)

	d := gomail.NewDialer("smtp.example.com", 587, "user", os.Getenv("PWD"))

	s, err := d.Dial()
	if err != nil {
		panic(err)
	}
	defer s.Close()

	if err := gomail.Send(s, m); err != nil {
		panic(err)
	}
}
