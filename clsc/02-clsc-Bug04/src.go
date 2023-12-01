// Comparison of identical expression
// Here p1.y < p1.y indicates a mistake
// CLSC should generate a warning

package testdata

type Point struct {
	x, y int
}

func comparePoint(p1, p2 Point) bool {
	if p1.x != 0 && p1.y != 0 {
		return p1.x < p2.x && p1.y < p1.y
	}
	return false
}

//<<<<<256, 267>>>>>
