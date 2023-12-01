// Issue 296
// Implementation of UnmarshalJSON has wrong signature.
// Warning will be given.

package testdata

type S struct{}

func (s *S) UnmarshalJSON(data []byte, pos int) error {
	return nil
}

//<<<<<131, 200>>>>>
