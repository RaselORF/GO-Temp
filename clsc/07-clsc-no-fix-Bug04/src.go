// Comparison of identical expression
// Here p1 != p1 compares identical expression,
// but warning will not be generated as this
// is for NaN check.

package testdata

func checkNan(p1 float64) bool {
	if p1 != p1 {
		return true
	}
	return false
}

//<<<<<208, 216>>>>>
