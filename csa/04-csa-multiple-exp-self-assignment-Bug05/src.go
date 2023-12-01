// Self assignment to 'x' and 'y'.
// CSA should generate a warning.

package testdata

type Point struct {
	x, y, z int
}

func (point *Point) setPoint(x, y, z int) {
	x, y, z = x, y, z
}

//<<<<<169, 186>>>>>
