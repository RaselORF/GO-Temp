// Comparison of identical expression
// Here p1.y < p1.y indicates a mistake
// CLSC should generate a warning

package testdata

type Point struct {
	x, y int
}

func comparePoint(p1, p2 Point) bool {
	var b bool = p1.x < p2.x && p1.y < p1.y
	return b
}

//<<<<<232, 243>>>>>
