// Issue 197
// Using loop variables in go statement. The goroutine
// may observe the wrong value of the variable.
// Fix should be generated.

package testdata

type node struct {
	val  int
	next *node
}

func main() {
	var head *node
	for p := head; p != nil; p = p.next {
		go func() {
			println(p.val)
		}()
	}
}

//<<<<<278, 313>>>>>
