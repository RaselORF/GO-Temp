// Issue 266
// Using untrusted input to construct an email is security sensitive.
// Warning will be given.

package main

import (
	"net/http"
	"net/smtp"
)

func mailHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("Host")
	token := "some_generated_token"
	body := "Click to reset password: " + host + "/" + token
	smtp.SendMail("test.test", nil, "from@from.com", nil, []byte(body))
}
