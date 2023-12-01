// Self assignment to 'y'.
// CSA should generate a warning.

package testdata

type Point struct {
	x, y int
}

func (point *Point) setPoint(x, y int) {
	point.x, y = x, y
}

//<<<<<155, 172>>>>>
