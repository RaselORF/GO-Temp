// Issue 296
// Implementation of MarshalXML has right signature.
// No warning will be given.

package testdata

import "encoding/xml"

type S struct{}

func (s *S) MarshalXML(d *xml.Encoder, start xml.StartElement) error {
	return nil
}

//<<<<<154, 238>>>>>
