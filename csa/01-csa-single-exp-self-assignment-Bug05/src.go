// Self assignment to 'name'.
// CSA should generate a warning.

package testdata

type User struct {
	name string
}

func (user *User) setName(name string) {
	name = name
}

//<<<<<160, 171>>>>>
