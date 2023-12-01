// Issue 176
// Passing tainted data into http.PostForm can
// result in request forgery.

package testdata

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func handler(w http.ResponseWriter, req *http.Request) {
	target := req.FormValue("targetURL")
	postUrl := fmt.Sprintf("https://%s.example.com/data/", target)
	formData := url.Values{
		"url": {"http://localhost:8080/secret"},
	}

	resp, err := http.PostForm(postUrl, formData)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer resp.Body.Close()

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Fprint(w, resp)
}

func main() {
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8090", nil)
}
