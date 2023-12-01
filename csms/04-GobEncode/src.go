// Issue 296
// Implementation of GobEncode has wrong signature.
// Warning will be given.

package testdata

type S struct{}

func (s S) GobEncode() []byte {
	return nil
}

//<<<<<127, 172>>>>>
