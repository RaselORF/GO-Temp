/*************************************************************************
 *
 * OPENREFACTORY CONFIDENTIAL
 * __________________
 *
 * Copyright (c) 2023 OpenRefactory, Inc. All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of OpenRefactory, Inc. The
 * intellectual and technical concepts contained herein are proprietary to OpenRefactory, Inc. and
 * may be covered by U.S. and Foreign Patents, patents in process, and are protected by trade secret
 * or copyright law. Dissemination of this information or reproduction of this material is strictly
 * forbidden unless prior written permission is obtained from OpenRefactory, Inc.
 *
 * Contributors: Rifat Rubayatul Islam (OpenRefactory, Inc.)
 *******************************************************************************/

package controlflow

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	cfg "github.com/OpenRefactory-Inc/icr-for-go/cfg_util"
	"github.com/OpenRefactory-Inc/icr-for-go/util"
	"github.com/OpenRefactory-Inc/icr-for-go/util/deque"
	"github.com/OpenRefactory-Inc/icr-for-go/util/set"
)

// IFlowNode denotes a node in the CFG
type IFlowNode interface {
	IsFlowNode() bool
	IsExitNode() bool
}

// FlowNode denotes an ast.Node
type FlowNode struct {
	Node ast.Node
}

func (FlowNode) IsFlowNode() bool {
	return true
}

func (FlowNode) IsExitNode() bool {
	return false
}

// exitNode denotes an abstract exit node.
// This type should not be used directly.
type exitNode struct {
}

func (exitNode) IsFlowNode() bool {
	return false
}

func (exitNode) IsExitNode() bool {
	return true
}

// FuncExit denotes a function exit
type FuncExit struct {
	exitNode
}

// OSExit denotes a program termination
type OSExit struct {
	exitNode
}

// PanicExit denotes a exit caused by panic
type PanicExit struct {
	exitNode
}

// SuccessorType denotes in which path a successor is found
type SuccessorType int

const (
	NormalPath SuccessorType = iota // Linear flow
	TruePath                        // True path of a condition
	FalsePath                       // False path of a condition
	PanicPath                       // Successor of a pinic
)

// SuccessorNode denotes a successor node in the CFG.
type SuccessorNode struct {
	Node     IFlowNode
	SuccType SuccessorType
}

// CFG denotes a control flow graph
type CFG struct {
	successorMap   map[IFlowNode][]SuccessorNode
	predecessorMap map[IFlowNode][]IFlowNode
	// processedBlks contains the entry nodes of each processed block.
	// If a block doesn't have any entry, it won't be present in this
	// map even if it is processed previously.
	processedBlks map[*cfg.Block][]IFlowNode
	// Issue 347
	// ancestorMap contains ancestor of each node in a function body.
	ancestorMap map[ast.Node]ast.Node
	fset        *token.FileSet
}

// CreateCFG creates CFG from cfg.CFG
func CreateCFG(functionBody *ast.BlockStmt, fs *token.FileSet) *CFG {
	fg := CFG{
		successorMap:         make(map[IFlowNode][]SuccessorNode),
		predecessorMap:       make(map[IFlowNode][]IFlowNode),
		processedBlks:        make(map[*cfg.Block][]IFlowNode),
		ancestorMap:          make(map[ast.Node]ast.Node),
		pendingMap:           make(map[ast.Node]*set.Set[ast.Node]),
		pendingResolutionMap: make(map[ast.Node][]SuccessorNode),
		fset:                 fs}

	// Build the cfg.CFG of the function
	base := cfg.New(functionBody, mayReturn)

	// seenBlocks keeps track of the blocks that are already visited
	seenBlocks := set.New[*cfg.Block]()
	// workList is a queue containig the blocks that are yet to be proccessed
	workList := deque.New[*cfg.Block]()

	// Block 0 is the entry block of the cfg.
	entries := fg.findEntry(base.Blocks[0], set.New[*cfg.Block]())
	for _, entry := range entries {
		// We will use nil to denote predecessor of the entry node
		fg.addSuccessor(nil, SuccessorNode{Node: entry, SuccType: NormalPath})
	}

	// We will start with the first block and traverse through the successors
	// until we have processed all the blocks
	workList.AddLast(base.Blocks[0])
	for !workList.IsEmpty() {
		curr, _ := workList.RemoveFirst()
		if seenBlocks.Contains(curr) {
			// This block is already processed
			// No need to process again
			continue
		}
		seenBlocks.Add(curr)

		fg.processBlock(curr)
		if curr == nil {
			// Nil denotes return block. It has no nodes and successors.
			// So, nothing to process
			continue
		}

		for _, succBlk := range curr.Succs {
			// Add the successors of the current block to the queue
			workList.AddLast(succBlk)
		}
	}
	return &fg
}

// A trivial mayReturn predicate that looks only at syntax, not types.
func mayReturn(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name != "panic"
	case *ast.SelectorExpr:
		return fun.Sel.Name != "Fatal"
	}
	return true
}

// addSuccessor adds the successor for the node. Also adds the node as
// the predecessor of the successor node.
func (fg *CFG) addSuccessor(node IFlowNode, succ SuccessorNode) {
	// Populate successor map
	fg.successorMap[node] = append(fg.successorMap[node], succ)

	// Populate predecessor map
	fg.predecessorMap[succ.Node] = append(fg.predecessorMap[succ.Node], node)
}

// processBlock processes a block of cfg.CFG and populates the successor
// and predecessor map
func (fg *CFG) processBlock(block *cfg.Block) {
	if block.Nodes == nil {
		// Empty block.
		// No need to process
		return
	}
	// Nodes inside a block will be processed sequentially
	prev := FlowNode{Node: block.Nodes[0]}

	for i := 1; i < len(block.Nodes); i++ {
		succ := FlowNode{Node: block.Nodes[i]}
		fg.addSuccessor(prev, SuccessorNode{Node: succ, SuccType: NormalPath})
		prev = succ
	}
	switch len(block.Succs) {
	case 0:
		// No successor
		// That means its an return block
		fg.addSuccessor(prev, SuccessorNode{Node: FuncExit{}, SuccType: NormalPath})
	case 1:
		// One successor block found. So, it will be a sequential node
		// i.e. Noramal path successor
		entries := fg.findEntry(block.Succs[0], set.New[*cfg.Block]())
		fmt.Print(block.Succs[0].String())
		for _, entry := range entries {
			fg.addSuccessor(prev, SuccessorNode{Node: entry, SuccType: NormalPath})
		}
	case 2:
		// Two successor blocks found. The first one will be the true path successor
		// and the second one is the false path successor
		entries := fg.findEntry(block.Succs[0], set.New[*cfg.Block]())
		for _, entry := range entries {
			fg.addSuccessor(prev, SuccessorNode{Node: entry, SuccType: TruePath})
		}
		fmt.Print(block.Succs[1])
		entries = fg.findEntry(block.Succs[1], set.New[*cfg.Block]())
		for _, entry := range entries {
			fg.addSuccessor(prev, SuccessorNode{Node: entry, SuccType: FalsePath})
		}
	default:
		// Should never come here
		util.TriggerError("More than 2 successors found", true)
	}
}

// findEntry finds the entry node of a block. If the block is empty
// It will recursively look for entry nodes in the successor blocks
// func (fg *CFG) findEntry(block *cfg.Block, seenBlocks *set.Set[*cfg.Block]) []IFlowNode {

// findEntry finds the entry node of a block. If the block is empty
// It will recursively look for entry nodes in the successor blocks
func (fg *CFG) findEntry(block *cfg.Block, seenBlocks *set.Set[*cfg.Block]) []IFlowNode {
	if res, ok := fg.processedBlks[block]; ok {
		// We have already processed this block
		// Get the result from the cache
		return res
	}

	if seenBlocks.Contains(block) {
		// We have seen this block before
		// but there is no entry in the cache
		// that means this block and its successor
		// creates a loop and there is no entry.
		// This may happen for loop with no condition
		// and empty body. For example:
		//
		// for range arr {
		// }
		//
		// Here, successor of `arr` is an empty block
		// for loop variable. Successor for that block
		// is another empty block for loop body.
		// Successor for the empty loop body block is
		// again the first block for loop variables.
		// No need to process it again.
		return []IFlowNode{}
	}
	seenBlocks.Add(block)

	if block.Nodes != nil {
		// First node of the block in the entry
		flNode := FlowNode{Node: block.Nodes[0]}
		entries := []IFlowNode{flNode}
		fg.processedBlks[block] = entries
		return entries
	}

	entries := make([]IFlowNode, 0, 2)
	// If we reach here, we haven't found any entry.
	// So, process the successor blocks
	for _, blk := range block.Succs {
		blkEntries := fg.findEntry(blk, seenBlocks)
		entries = append(entries, blkEntries...)
		fg.processedBlks[blk] = blkEntries
	}
	return entries
}

// Issue 79
//
// FixCfgForTypeSwitch rectifies the cfg for the TypeSwitch
// The default CFG of go doesn't contain the type names in
// the case clauses. Successors of the assignment node of the
// type switch are the first statements of every case block
// But we need the type names as well to generate constraint
// So, we are updating the CFG to look like normal SwitchStmt.
// For example:
//
//	 func foo(n interface{}) string {
//		    var msg string
//		    switch n.(type) {
//		    case int, float64:
//		        msg = "number"
//		    case string:
//		        msg = "text"
//		    default:
//		        msg = "unknown"
//		    }
//		    return msg
//	 }
//
// Here, the cfg will look like
//
//	            msg string
//	               |
//	            n.(type)
//	               |
//	              int
//	   (true)  /        \  (false)
//	          /          \
//	msg = "number" <---- float64
//	       |       (true)   \ (false)
//	       |                 \
//	       |                string
//	       |        (true) /      \ (false)
//	       |              /        \
//	        \   msg = "text"    msg = "unknown"
//	         \        |         /
//	          \       |        /
//	           \      |       /
//	              return res
func (fg *CFG) FixCfgForTypeSwitch(ts *ast.TypeSwitchStmt) {
	assignNode := FlowNode{Node: ts.Assign}
	// Save the successors of the assign node
	successors := fg.successorMap[assignNode]
	// Remove all the current successors of the
	// assign node. New successor will be added
	// later in the code.
	fg.removeAllSuccessors(assignNode)
	// The successor of the assign node is the
	// first type inside the first case clause
	// It will be a direct successor
	prev, succType := assignNode, NormalPath
	succIdx := 0
	for _, stmt := range ts.Body.List {
		// TypeSwitchStmt.Body contains case clauses only
		// So, it is safe to cast here.
		cc := stmt.(*ast.CaseClause)
		if cc.List != nil {
			// Not the default case
			// Take the first type and add it as a
			// successor of the previous node
			curr := FlowNode{Node: cc.List[0]}
			succ := SuccessorNode{Node: curr, SuccType: succType}
			fg.addSuccessor(prev, succ)

			// Make the old successor (entry of the case block)
			// as the true path successor of the type.
			old := successors[succIdx]
			tpSucc := SuccessorNode{Node: old.Node, SuccType: TruePath}
			fg.addSuccessor(curr, tpSucc)

			succIdx++
			prev = curr
			for i := 1; i < len(cc.List); i++ {
				// Multiple types inside same case
				// Make the current one the false path successor
				// of the previous one.
				// They will have the same true path successor
				curr = FlowNode{Node: cc.List[i]}
				succ = SuccessorNode{Node: curr, SuccType: FalsePath}
				fg.addSuccessor(prev, succ)
				fg.addSuccessor(curr, tpSucc)

				succIdx++
				prev = curr
			}
		}
		// After the first one, rest of the case types
		// can only be the false path successor of the
		// previous type
		succType = FalsePath
	}

	// For the last case, false path successor will be
	// the entry of the default or entry of the next statement
	// after the type switch if there is no default.
	// We don't need to find it manually
	// as it will the last enrty of the old successor list
	old := successors[len(successors)-1]
	succ := SuccessorNode{Node: old.Node, SuccType: FalsePath}
	fg.addSuccessor(prev, succ)
}

// Issue 95
//
// FixCfgForSelect rectifies the cfg for the SelectStmt.
// The default CFG of go puts all the case (CommClause) expressions
// sequentially and puts all the CommClause bodies as the successor
// of the last CommClause expression. We fix this CFG by adding the
// body as the successor of the respective CommClause expression.
// The next CommClause expression becomes the false path successor
// of the previous one. For example:
//
//		func bar(c1, quit chan int, c2 chan string) string {
//		    var res string
//		    x := 0
//		    select {
//		    case c1 <- x:
//	         fmt.Println()
//		    case m := <-c2:
//		        res = m
//		    default:
//		        res = "quit"
//		    }
//		    return res
//		}
//
// Here, the cfg will look like
//
//	            res string
//	               |
//	            c1 <- x
//	   (true)  /       \  (false)
//	          /         \
//	fmt.Println()      m := <-c2
//	       |     (true) /      \ (false)
//	       |           /        \
//	        \      res = m    res = "quit"
//	         \        |        /
//	          \       |       /
//	           \      |      /
//	              return res
func (fg *CFG) FixCfgForSelect(sel *ast.SelectStmt) {
	comms := sel.Body.List
	n := len(comms)
	if n == 0 {
		// There is no CommClause inside.
		// Nothing to fix.
		return
	}

	// Find the first non-default CommClause and its index
	var firstCom *ast.CommClause
	var firstComIdx int
	for idx, stmt := range comms {
		cc := stmt.(*ast.CommClause)
		if cc.Comm != nil {
			firstCom = cc
			firstComIdx = idx
			break
		}
	}

	// Find the last non-default CommClause
	var lastCom *ast.CommClause
	for i := n - 1; i >= 0; i-- {
		cc := comms[i].(*ast.CommClause)
		if cc.Comm != nil {
			lastCom = cc
			break
		}
	}

	lastCommNode := FlowNode{Node: lastCom.Comm}
	// Succeessors of the last comm clause contains
	// all the entry nodes of each comm body. For some weird
	// reason the deafult CFG makes the entry nodes as the
	// successor of the last comm clause. We need to map it with
	// each comm expression. So, save it for later mapping.
	actualSuccs := fg.successorMap[lastCommNode]
	// Remove all the current successors of the last comm node.
	// New successor will be added later.
	fg.removeAllSuccessors(lastCommNode)

	succIdx := 0
	// Start with the first CommClasue, then update the successors
	// progressively. True path successor will be taken from existing
	// succeesor and the false path successor will be the expression
	// of the next CommClause.
	firstComNode := FlowNode{Node: firstCom.Comm}
	fg.removeAllSuccessors(firstComNode)
	fg.updateSuccForCommClause(firstCom, firstComNode, actualSuccs[succIdx].Node)
	succIdx++

	prev := firstComNode
	for i := firstComIdx + 1; i < n; i++ {
		// SelectStmt.Body contains comm clauses only
		// So, it is safe to cast here.
		cc := comms[i].(*ast.CommClause)
		if cc.Comm != nil {
			// Not the default case
			// Remove existing successors
			curr := FlowNode{Node: cc.Comm}
			fg.removeAllSuccessors(curr)
			fg.updateSuccForCommClause(cc, curr, actualSuccs[succIdx].Node)

			// Make the current one the false path successor
			// of the previous one.
			succ := SuccessorNode{Node: curr, SuccType: FalsePath}
			fg.addSuccessor(prev, succ)

			succIdx++
			prev = curr
		}
	}

	// For the last case, false path successor will be
	// the entry of the default. If there is no default,
	// there is no false path successor. Because select is
	// a blocking statement. It will block until one of the
	// channel is ready. So, there is no option to reach the
	// next statement without executing any of the case.
	// We don't need to look for the default, as there will a
	// successor in the original successor list if it is present.
	if succIdx < n {
		old := actualSuccs[succIdx]
		succ := SuccessorNode{Node: old.Node, SuccType: FalsePath}
		fg.addSuccessor(prev, succ)
	}
}

// Issue 95
//
// updateSuccForCommClause fixes successor for CommClause expression.
// It takes the comm clause, the predecessor node (which is the expression
// of the comm clause) and the actual successor of the pred. It will then
// replace the current successor of the pred with the actual successor.
func (fg *CFG) updateSuccForCommClause(cc *ast.CommClause, pred, actualSucc IFlowNode) {
	if _, ok := cc.Comm.(*ast.AssignStmt); ok {
		// If there is a assignment inside CommClause expression
		// the default CFG creates an extra successor.
		// For example:
		//     case m := <-c2:
		//	        res = m
		// will have successor like following
		// m := <-c2 ----> m ----> res = m
		// We don't nedd the extra successor m.
		// So, we will remove it and link its predecessor and successor
		succOfAssgnment := fg.successorMap[actualSucc]
		fg.removeAllSuccessors(actualSucc)
		for _, sa := range succOfAssgnment {
			fg.addSuccessor(pred, sa)
		}
	} else {
		// Make the old successor (entry of the case block)
		// as the true path successor of the comm node.
		succ := SuccessorNode{Node: actualSucc, SuccType: TruePath}
		fg.addSuccessor(pred, succ)
	}
}

// Issue 79
//
// removeAllSuccessors removes the given node from successorMap.
// It also removes the node from the prdecessor list of the deleted
// successor nodes. If the given node is not found inside successorMap
// this method has no impact.
func (fg *CFG) removeAllSuccessors(node IFlowNode) {
	successors, ok := fg.successorMap[node]
	if !ok {
		return
	}
	// Remove the node from successor map
	delete(fg.successorMap, node)

	seenSuccs := set.New[IFlowNode]()
	// Update the precessor map for each successor
	for _, succ := range successors {
		if seenSuccs.Contains(succ.Node) {
			// Already processed
			continue
		}
		seenSuccs.Add(succ.Node)

		predecessors := fg.predecessorMap[succ.Node]
		newPredecessors := make([]IFlowNode, 0, len(predecessors)-1)
		for _, pred := range predecessors {
			if pred != node {
				// Add all the existing predecessor
				// that is not the given node
				newPredecessors = append(newPredecessors, pred)
			}
		}
		if len(newPredecessors) > 0 {
			fg.predecessorMap[succ.Node] = newPredecessors
		} else {
			// No predecessor left for the node
			// Remove it from the map
			delete(fg.predecessorMap, succ.Node)
		}
	}
}

// SuccessorsOf retruns the successors of the given flow node
func (fg *CFG) SuccessorsOf(node ast.Node) []SuccessorNode {
	return fg.SuccessorsOfFlowNode(FlowNode{Node: node})
}

// SuccessorsOfFlowNode retruns the successors of the given flow node
func (fg *CFG) SuccessorsOfFlowNode(node IFlowNode) []SuccessorNode {
	return fg.successorMap[node]
}

// PredecessorsOf retruns the predecessors of the given ast node
func (fg *CFG) PredecessorsOf(node ast.Node) []IFlowNode {
	return fg.PredecessorsOfFlowNode(FlowNode{Node: node})
}

// PredecessorsOfFlowNode retruns the predecessors of the given flow node
func (fg *CFG) PredecessorsOfFlowNode(node IFlowNode) []IFlowNode {
	return fg.predecessorMap[node]
}

// String returns a formatted string representation of the CFG
func (fg *CFG) String() string {
	buider := strings.Builder{}
	buider.WriteString("----------------------------CFG---------------------------\n")
	buider.WriteString("SuccessorMap:\n")
	for node, successors := range fg.successorMap {
		buider.WriteString("\t")
		buider.WriteString(FlowNodeString(node, fg.fset))
		buider.WriteString("==>{")
		for i, sn := range successors {
			if i != 0 {
				buider.WriteString(", ")
			}
			buider.WriteString(SuccessorNodeString(sn, fg.fset))
		}
		buider.WriteString("},\n")
	}
	buider.WriteString("\n")
	buider.WriteString("PredecessorMap:\n")
	for node, preds := range fg.predecessorMap {
		buider.WriteString("\t")
		buider.WriteString(FlowNodeString(node, fg.fset))
		buider.WriteString("==>{")
		for i, fn := range preds {
			if i != 0 {
				buider.WriteString(", ")
			}
			buider.WriteString(FlowNodeString(fn, fg.fset))
		}
		buider.WriteString("},\n")
	}
	buider.WriteString("----------------------------------------------------------\n")
	return buider.String()
}

// SuccessorNodeString returns a string representation of SuccessorNode
func SuccessorNodeString(sn SuccessorNode, fs *token.FileSet) string {
	buider := strings.Builder{}
	buider.WriteString("<SuccType: ")
	switch sn.SuccType {
	case TruePath:
		buider.WriteString("true")
	case FalsePath:
		buider.WriteString("false")
	case PanicPath:
		buider.WriteString("panic")
	default:
		buider.WriteString("normal")
	}
	buider.WriteString(", Node: ")
	buider.WriteString(FlowNodeString(sn.Node, fs))
	buider.WriteString(">")
	return buider.String()
}

// FlowNodeString returns a string representation of IFlowNode
func FlowNodeString(node IFlowNode, fs *token.FileSet) string {
	switch fnode := node.(type) {
	case FlowNode:
		str, _ := util.GetNodeStr(fnode.Node, fs)
		return str
	case FuncExit:
		return "FuncExit"
	case PanicExit:
		return "PanicExit"
	case OSExit:
		return "OSExit"
	case nil:
		return "Entry"
	}
	return "Invalid Node"
}

// Issue 347
//
// Populate ancestor map for each node of given block statement node
func (cfg *CFG) PopulateAncestorMap(node, parent ast.Node) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *ast.SelectStmt:
		// Issue 95
		// Select is like a switch without test expression.
		// we need to fix the control flow first.
		cfg.FixCfgForSelect(n)
	case *ast.TypeSwitchStmt:
		// Issue 79
		// Before processing any thing in a type switch
		// we need to fix the control flow first.
		// Otherwise we won't get correct predecessor and successor.
		// cfg.FixCfgForTypeSwitch(n)
	}
	cfg.ancestorMap[node] = parent
	// If the node is a FuncLit, we won't dig down in it.
	if _, ok := node.(*ast.FuncLit); !ok {
		ast.Inspect(node, func(child ast.Node) bool {
			if child != node {
				cfg.PopulateAncestorMap(child, node)
				return false
			}
			return true
		})
	}
}
