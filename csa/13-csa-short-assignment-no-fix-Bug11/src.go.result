// Short assignment declaration of 'v'.
// CSA should not generate a warning.

package testdata

import "fmt"

func main() {
	done := make(chan bool)

	values := []string{"a", "b", "c"}
	for _, v := range values {
		v := v
		go func() {
			fmt.Println(v)
			done <- true
		}()
	}
	for range values {
		<-done
	}
}

//<<<<<216, 222>>>>>
