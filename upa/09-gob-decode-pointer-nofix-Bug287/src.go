// Issue 89
// Should avoid Passing hard coded credential into tls.X509KeyPair
// Flaky test
// Taint trace message sometimes indicates that taint is coming from certPEM,
// sometimes indicates keyPEM as taint source.

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"text/template/parse"
)

type Template struct {
	name string
	*parse.Tree
	leftDelim  string
	rightDelim string
}

func (*Template) Execute() error {
	return nil
}

func getTemp() (*Template, error) {
	return &Template{}, nil
}
func ExecuteTextString(text string) string {
	if text == "" {
		return ""
	}
	tmpl, err := getTemp()
	if err != nil {
		return ""
	}
	tmpl, err = getTemp()
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	err = tmpl.Execute()
	return buf.String()
}

func TmplText() func(string) string {
	return func(name string) (s string) {
		s = ExecuteTextString(name)
		return s
	}
}

var APIKey string
var APIKeyFile string

func Foo(req *http.Request) {
	tmpl := TmplText()
	var apiKey string
	if APIKey != "" {
		apiKey = tmpl(string(APIKey))
	} else {
		content, err := os.ReadFile(APIKeyFile)
		if err != nil {
			return
		}
		apiKey = tmpl(string(content))
	}
	req.Header.Set("Authorization", fmt.Sprintf("GenieKey %s", apiKey))
}
