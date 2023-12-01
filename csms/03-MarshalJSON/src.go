// Issue 296
// Implementation of MarshalJSON has wrong signature.
// Warning will be given.

package testdata

type S struct{}

func (s S) MarshalJSON() []byte {
	return nil
}

//<<<<<129, 176>>>>>
