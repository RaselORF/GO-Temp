// Issue 308
// Don't use hard coded state in OAuth 2.0 clients

package main

import (
	"fmt"

	"golang.org/x/oauth2"
)

func main() {}

var stateStringVar = "state"

func BadWithStringLiteralState() {
	conf := &oauth2.Config{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		Scopes:       []string{"SCOPE1", "SCOPE2"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://provider.com/o/oauth2/auth",
			TokenURL: "https://provider.com/o/oauth2/token",
		},
	}
	url := conf.AuthCodeURL(stateStringVar)
	fmt.Print(url)
}
