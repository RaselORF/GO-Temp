// Not a self assignment, no warning from CSA.

package testdata

type Point struct {
	x, y int
}

func (point *Point) setPoint(x, y int) {
	point.x, point.y = x, y
}

//<<<<<141, 164>>>>>
