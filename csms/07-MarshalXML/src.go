// Issue 296
// Implementation of MarshalXML has wrong signature.
// Warning will be given.

package testdata

import "encoding/xml"

type S struct{}

func (s *S) MarshalXML(d *xml.Decoder, start xml.StartElement) (error, bool) {
	return nil, true
}

//<<<<<151, 249>>>>>
