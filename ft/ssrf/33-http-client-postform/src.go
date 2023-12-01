// Issue 176
// Passing tainted data into http.Client.PostForm can
// result in request forgery.

package testdata

import (
	"fmt"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, req *http.Request) {
	target := req.FormValue("targetURL")
	postUrl := fmt.Sprintf("https://%s.example.com/data/", target)
	client := &http.Client{}

	// Create a URL-encoded form data
	data := url.Values{}
	data.Set("username", "johndoe")
	data.Set("password", "secretpassword")
	resp, err := client.PostForm(postUrl, data)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprint(w, resp)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
