// Issue 296
// Implementation of UnmarshalXML has wrong signature.
// Warning will be given.

package testdata

import "encoding/xml"

type S struct{}

func (s *S) UnmarshalXML(d *xml.Decoder, start xml.StartElement) (error, bool) {
	return nil, true
}

//<<<<<153, 253>>>>>
