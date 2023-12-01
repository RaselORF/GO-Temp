block 1 (range.loop)block 4 (typeswitch.done)block 4 (typeswitch.done).0: # entry
	msg []string
	msg
	idx
	val
	succs: 1

.1: # range.loop
	succs: 2 3

.2: # range.body
	n.(type)
	succs: 5 6

.3: # range.done
	return true

.4: # typeswitch.done
	succs: 1

.5: # typeswitch.body
	fmt.Print("string", idx, val)
	succs: 4

.6: # typeswitch.next
	succs: 7 8

.7: # typeswitch.body
	succs: 4

.8: # typeswitch.next
	succs: 9 10

.9: # typeswitch.body
	succs: 4

.10: # typeswitch.next
	fmt.Print("default")
	succs: 4

.11: # unreachable.return