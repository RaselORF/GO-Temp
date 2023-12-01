// Self assignment in switch statement. Warning
// should be over switch statement.

package testdata

func isDivByThree(a int) bool {
	switch a = a; a % 3 {
	case 0:
		return true
	case 1, 2:
		return false
	}
	return false
}

//<<<<<143, 148>>>>>
