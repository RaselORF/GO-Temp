// Issue 197
// loop variable is assigned to a new variable and that
// is used inside go statement.
// Fix should not be generated.

package testdata

type node struct {
	val  int
	next *node
}

func main() {
	var head *node
	for p := head; p != nil; p = p.next {
		p := p
		go func() {
			println(p.val)
		}()
	}
}

//<<<<<276, 311>>>>>
