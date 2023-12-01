// Issue 89
// Writting tainted data into goxpath.ParseExec can
// result in Xpath injection.

package main

import (
	"fmt"
	"net/http"

	"github.com/ChrisTrenkamp/goxpath"
	"github.com/ChrisTrenkamp/goxpath/tree"
)

func main() {}

func processRequest(r *http.Request, doc tree.Node) {
	r.ParseForm()
	username := r.Form.Get("username")

	unsafeRes, _ := goxpath.ParseExec("//users/user[login/text()='"+username+"']/home_dir/text()", doc)
	fmt.Println(unsafeRes)
}
