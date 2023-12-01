// Issue 89
// Writting tainted data into goxpath.ExecNode can
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

	xPath, _ := goxpath.Parse("//users/user[login/text()='" + username + "']/home_dir/text()")
	unsafeRes, _ := xPath.ExecNode(doc)
	fmt.Println(unsafeRes)
}
