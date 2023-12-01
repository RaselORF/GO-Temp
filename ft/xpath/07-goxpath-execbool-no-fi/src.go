// Issue 89
// Writting tainted data into goxpath.ExecBool can
// result in Xpath injection. But safe if ses parameters
// to avoid including user input directly in XPath expression

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

	opt := func(o *goxpath.Opts) {
		o.Vars["username"] = tree.String(username)
	}
	xPath := goxpath.MustParse("//users/user[login/text()=$username]/home_dir/text()")
	safeRes, _ := xPath.ExecBool(doc, opt)
	fmt.Println(safeRes)
}
