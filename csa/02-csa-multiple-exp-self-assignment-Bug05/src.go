// Self assignment to 'x' and 'y'.
// CSA should generate a warning.

package testdata

type Point struct {
	x, y int
}

func (point *Point) setPoint(x, y int) {
	x, y = x, y
}

//<<<<<163, 174>>>>>
