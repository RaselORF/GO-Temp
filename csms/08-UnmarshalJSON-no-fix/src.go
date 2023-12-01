// Issue 296
// Implementation of UnmarshalJSON has right signature.
// No warning will be given.

package testdata

type S struct{}

func (s *S) UnmarshalJSON(data []byte) error {
	return nil
}

//<<<<<134, 194>>>>>
