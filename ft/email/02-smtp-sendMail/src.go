// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

package main

import (
	"net/http"
	"net/smtp"
)

func mailHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Form.Get("user")
	body := "Hello " + user + "Welcome"
	smtp.SendMail("test.test", nil, "from@from.com", nil, []byte(body))
}
