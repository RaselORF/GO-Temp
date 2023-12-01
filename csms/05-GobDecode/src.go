// Issue 296
// Implementation of GobDecode has wrong signature.
// Warning will be given.

package testdata

type S struct{}

func (s *S) GobDecode(data []byte) (error, bool) {
	return nil, true
}

//<<<<<127, 197>>>>>
