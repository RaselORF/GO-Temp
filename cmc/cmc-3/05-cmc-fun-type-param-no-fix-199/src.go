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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/OpenRefactory-Inc/icr-for-go/util"
	"github.com/OpenRefactory-Inc/icr-for-go/util/set"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/cfg"
)

// TestCFG performs sanity check for CFG.
// In a CFG, if node X is successor of node Y
// then Y must be the predecessor of node X
// and vice varsa.
func TestCFG(t *testing.T) {
	testFolderName := "../pointer/testdata/01.go"
	testFiles, err := util.GetAllFiles(testFolderName)
	if err != nil {
		t.Fatal(err)
	}
	for _, testFile := range testFiles {
		if filepath.Ext(testFile) != ".go" {
			continue
		}
		testFilePath, _ := filepath.Abs(testFile)
		packageList, err := util.LoadTestFile(testFile)
		if err != nil {
			t.Error(err)
		}
		if len(packageList) == 0 {
			t.Errorf("For file : %s, package informations not found\n", testFilePath)
		}
		pkg := packageList[0]
		astList := pkg.Syntax
		if len(astList) == 0 {
			t.Errorf("In file : %s, ast list found empty\n", testFilePath)
		}
		util.PopulatePkgInfo(packageList)

		// Load the current ast and parse the markers
		curAst := astList[0]
		fset := pkg.Fset
		// Find all the function declarations inside the test file.
		functions := util.GetAllFunctionDecl(curAst)

		for _, f := range functions {
			// Run a sub-test for each function
			t.Run(fmt.Sprintf("File:%s,Function:%s", testFilePath, f.Name.Name),
				func(t *testing.T) {
					checkEachFunc(f, fset, t)
				})
		}
	}
}

// checkEachFunc tests cfg for a function
func checkEachFunc(f *ast.FuncDecl, fset *token.FileSet, t *testing.T) {
	fg := CreateCFG(f.Body, fset)
	fg.PopulateAncestorMap(f.Body, f)
	// Check the successor map
	base := cfg.New(f.Body, MayReturn)
	fmt.Print(base.Format(fset))
	for node, successors := range fg.successorMap {
		fmt.Print(FlowNodeString(node, fg.fset), "\n")
		for _, succ := range successors {
			if predecessors, ok := fg.predecessorMap[succ.Node]; !ok {
				t.Errorf("No prdecessor found for node %s", FlowNodeString(succ.Node, fg.fset))
			} else if !slices.Contains(predecessors, node) {
				t.Errorf("Node %s is not a predecessor of node %s",
					FlowNodeString(node, fg.fset), FlowNodeString(succ.Node, fg.fset))
			}
			fmt.Print(FlowNodeString(succ.Node, fg.fset), ", ")
		}
		fmt.Print("\n\n")
	}
	fmt.Print("temp")
	// Check the predecessor map
	for node, predecessors := range fg.predecessorMap {
		for _, pred := range predecessors {
			if successors, ok := fg.successorMap[pred]; !ok {
				t.Errorf("No prdecessor found for node %s", FlowNodeString(pred, fg.fset))
			} else {
				predicate := func(succ SuccessorNode) bool {
					return succ.Node == node
				}
				if !slices.ContainsFunc(successors, predicate) {
					t.Errorf("Node %s is not a successor of node %s",
						FlowNodeString(node, fg.fset), FlowNodeString(pred, fg.fset))
				}
			}
		}
	}
}

// Issue 347
//
// TestCFGParentMap tests if ancestor map is populated properly in cfg or not.
// Test Format:
// [
//
//		<test-type>, <num-of-test>,
//	    [
//			<func-token range>, <node token range>,
//		]
//	    ...........................
//
// ]
// Test-types  =>  PARENT_TEST
// Here [] is used to specify list, they will not appear in test case
// For example
//
// <<<<<
//
//	 PARENT_TEST, 3,
//		134::269, 153, 254,
//		134::269, 157, 158,
//		134::269, 162, 164
//
// >>>>>
func TestCFGParentMap(t *testing.T) {
	testFolderName := "testdata/parent-map"
	testFiles, err := util.GetAllFiles(testFolderName)
	if err != nil {
		t.Fatal(err)
	}
	for _, testFile := range testFiles {
		if filepath.Ext(testFile) != ".go" {
			continue
		}
		testFilePath, _ := filepath.Abs(testFile)
		packageList, err := util.LoadTestFile(testFile)
		if err != nil {
			t.Error(err)
		}
		if len(packageList) == 0 {
			t.Errorf("For file : %s, package informations not found\n", testFilePath)
		}
		pkg := packageList[0]
		astList := pkg.Syntax
		if len(astList) == 0 {
			t.Errorf("In file : %s, ast list found empty\n", testFilePath)
		}
		util.PopulatePkgInfo(packageList)
		// Load the current ast and parse the markers
		curAst := astList[0]
		fset := pkg.Fset
		// Find all the function declarations inside the test file.
		funcMap := make(map[string]ast.Node)
		allFunctions := util.GetAllFunctions(curAst, false)
		for _, function := range allFunctions {
			offsetStr := fmt.Sprintf("%d::%d", fset.Position(function.Pos()).Offset,
				fset.Position(function.End()).Offset)
			funcMap[offsetStr] = function
		}
		markerList, err := util.ParseMarkers(curAst, fset)
		if err != nil {
			t.Logf("In file : %s, %v\n", testFilePath, err)
			continue
		}
		for testType := markerList.RemoveFirst(); testType != ""; testType = markerList.RemoveFirst() {
			if testType != "PARENT_TEST" {
				continue
			}
			numOfTests, err := strconv.Atoi(markerList.RemoveFirst())
			if err != nil {
				t.Error(err)
			}
			for i := 1; i <= numOfTests; i++ {
				offsetStr := markerList.RemoveFirst()
				targetFunc := funcMap[offsetStr]
				// Assert matching function found
				if targetFunc == nil {
					t.Errorf("In file : %s, no function found with token range %s\n",
						testFilePath, offsetStr)
				}
				// get start and end offset of node whose parent is to be checked
				startOffset, err := strconv.Atoi(markerList.RemoveFirst())
				if err != nil {
					t.Error(err)
				}
				endOffset, err := strconv.Atoi(markerList.RemoveFirst())
				if err != nil {
					t.Error(err)
				}
				// Run a sub-test for each function
				t.Run(fmt.Sprintf("File:%s,token range:%s", testFilePath, offsetStr),
					func(t *testing.T) {
						checkParent(curAst, targetFunc, fset, t, startOffset, endOffset)
					})
			}
		}
	}
}

// checkParent checks if parent node of given node is properly populated or not.
// f is the funcDecl/funcLit node that contains the node to be checked.
// startOffset and endOffset is the offset of the node to be checked.
func checkParent(curAst *ast.File, f ast.Node, fset *token.FileSet,
	t *testing.T, startOffset, endOffset int) {
	var fg *CFG
	var funcBody *ast.BlockStmt
	switch fn := f.(type) {
	case *ast.FuncDecl:
		funcBody = fn.Body
	case *ast.FuncLit:
		funcBody = fn.Body
	default:
		t.Errorf("Node is not a FuncDecl or FuncLit\n")
		return
	}
	fg = CreateCFG(funcBody, fset)
	fg.PopulateAncestorMap(funcBody, f)
	var matchedNode ast.Node
	var curStack []ast.Node
	matchedNode, curStack = getNodeFromOffset(curAst, fset, startOffset, endOffset)
	if matchedNode == nil {
		t.Errorf("Nil node is selected. Start Offset: %d, End Offset: %d\n",
			startOffset, endOffset)
		return
	}
	ancestor := fg.ancestorMap[matchedNode]
	if ancestor != curStack[len(curStack)-2] {
		generated, _ := util.GetNodeStr(ancestor, fset)
		expected, _ := util.GetNodeStr(curStack[len(curStack)-2], fset)
		t.Errorf("For node of token range %d,%d Generated ancestor: %s\nExpected ancestor: %s\n",
			startOffset, endOffset, generated, expected)
	}
}

// getNodeFromOffset returns the ast.Node of given start and end offset and parents node list of the expected
func getNodeFromOffset(file *ast.File, fset *token.FileSet,
	startOffset, endOffset int) (ast.Node, []ast.Node) {
	var matchedNode ast.Node
	var curStack []ast.Node
	// Search the target node with the start and end offset
	ast.Inspect(file, func(n ast.Node) bool {
		if n != nil && n.Pos().IsValid() {
			startPos := fset.Position(n.Pos())
			endPos := fset.Position(n.End())
			if endPos.Offset < startOffset || startPos.Offset > endOffset {
				// Out of our search range
				// No need to check the childrens
				return false
			}
			curStack = append(curStack, n)
			if startPos.Offset == startOffset && endPos.Offset == endOffset {
				matchedNode = n
				return false
			}
		}
		return true
	})
	return matchedNode, curStack
}

// getFlowNodeFromMarker returns expected FlowNode from the token range stored in given marker list
func getFlowNodeFromMarker(markers *util.MarkerList, path string, fg *CFG,
	file *ast.File, fset *token.FileSet, sb *strings.Builder) IFlowNode {
	markerStr := markers.RemoveFirst()
	sb.WriteString("," + markerStr)
	startOffset, err := strconv.Atoi(markerStr)
	if err != nil {
		return nil
	}
	markerStr = markers.RemoveFirst()
	sb.WriteString("," + markerStr)
	endOffset, err := strconv.Atoi(markerStr)
	if err != nil {
		return nil
	}
	var node IFlowNode = nil
	if startOffset == -1 && endOffset == -1 {
		node = FuncExit{}
	} else if startOffset == -3 && endOffset == -3 {
		node = OSExit{}
	} else if startOffset == -2 && endOffset == -2 {
		node = PanicExit{}
	} else if startOffset == -4 && endOffset == -4 {
		// assign a dummy return node
		node = FlowNode{
			Node: &ast.ReturnStmt{},
		}
	} else {
		if startOffset < 0 || endOffset < 0 {
			return nil
		}
		selectedNode, _ := getNodeFromOffset(file, fset, startOffset, endOffset)
		if selectedNode == nil {
			return nil
		}
		node = FlowNode{
			Node: selectedNode,
		}
	}
	return node
}

// Issue 351
//
// Test suite for dominator
func TestDominator(t *testing.T) {
	testFolderName := "testdata/dominator"
	testFiles, err := util.GetAllFiles(testFolderName)
	if err != nil {
		t.Fatal(err)
	}
	for _, testFile := range testFiles {
		if filepath.Ext(testFile) != ".go" {
			continue
		}
		testFilePath, _ := filepath.Abs(testFile)
		packageList, err := util.LoadTestFile(testFile)
		if err != nil {
			t.Error(err)
		}
		if len(packageList) == 0 {
			t.Errorf("For file : %s, package informations not found\n", testFilePath)
		}
		pkg := packageList[0]
		astList := pkg.Syntax
		if len(astList) == 0 {
			t.Errorf("In file : %s, ast list found empty\n", testFilePath)
		}

		util.PopulatePkgInfo(packageList)
		// Load the current ast and parse the markers
		curAst := astList[0]
		fset := pkg.Fset
		// Find all the function declarations inside the test file.
		funcMap := make(map[string]ast.Node)
		allFunctions := util.GetAllFunctions(curAst, false)
		for _, function := range allFunctions {
			offsetStr := fmt.Sprintf("%d::%d", fset.Position(function.Pos()).Offset,
				fset.Position(function.End()).Offset)
			funcMap[offsetStr] = function
		}

		markerList, err := util.ParseMarkers(curAst, fset)
		if err != nil {
			t.Logf("In file : %s, %v\n", testFilePath, err)
			continue
		}
		if len(markerList) == 0 {
			t.Errorf("In file : %s, no marker is found", testFilePath)
			continue
		}
		for offsetStr := markerList.RemoveFirst(); offsetStr != ""; offsetStr = markerList.RemoveFirst() {
			var markerSb strings.Builder
			markerSb.WriteString(offsetStr)
			targetFunc := funcMap[offsetStr]
			// Assert matching function found
			if targetFunc == nil {
				t.Errorf("In file : %s, no function found with token range %s\n", testFilePath, offsetStr)
			}
			// Create control flow graph
			var fnBody *ast.BlockStmt
			switch fn := targetFunc.(type) {
			case *ast.FuncDecl:
				fnBody = fn.Body
			case *ast.FuncLit:
				fnBody = fn.Body
			default:
				t.Errorf("Selected node is not a FuncDecl or FuncLit\n")
				return
			}
			fg := CreateCFG(fnBody, fset)

			flowNode := getFlowNodeFromMarker(&markerList, testFilePath, fg, curAst, fset, &markerSb)
			if flowNode == nil {
				t.Errorf("Nil Node selected")
			}

			dom := CreateDominator(fg)
			actualDominators := dom.getDominator(flowNode)
			if actualDominators == nil {
				t.Errorf("For file : %s, Dominators found nil\n", testFilePath)
			}
			markerStr := markerList.RemoveFirst()
			markerSb.WriteString("," + markerStr)
			dominatorCount, err := strconv.Atoi(markerStr)
			if err != nil {
				t.Error(err)
			}

			expectedDominators := *set.New[IFlowNode]()
			for i := 0; i < dominatorCount; i++ {
				node := getFlowNodeFromMarker(&markerList, testFilePath, fg, curAst, fset, &markerSb)
				expectedDominators.Add(node)
			}

			var actualDomSb strings.Builder
			for _, actualDominator := range actualDominators.Elements() {
				actualDomSb.WriteString(FlowNodeString(actualDominator, fset))
				actualDomSb.WriteString("#")
			}

			if len(expectedDominators.Elements()) != len(actualDominators.Elements()) {
				t.Errorf("In file %s, marker: %s, for node %s, dominator count doesn't match match. Expected : %d,"+
					" Found : %d, \nActualSet: %s\n", testFilePath, markerSb.String(), FlowNodeString(flowNode, fset),
					len(expectedDominators.Elements()), len(actualDominators.Elements()), actualDomSb.String())
			}

			for _, expectedDominator := range expectedDominators.Elements() {
				if !actualDominators.Contains(expectedDominator) {
					if flowNode, ok := expectedDominator.(FlowNode); ok {
						if _, ok := flowNode.Node.(*ast.ReturnStmt); ok {
							continue
						}
					}
					t.Errorf(
						"Dominator not found in file: %s, marker: %s,  for node: %s expected node : %s,"+
							" but actual dominator set is :\n%s\n", testFilePath, markerSb.String(),
						FlowNodeString(flowNode, fset), FlowNodeString(expectedDominator, fset), actualDomSb.String())
				}
			}
		}
	}
}

// Issue 354
//
// Test suite for post dominator
// Test Format:
// [
//
//		<func-token range>, <node token range>, <post dom count>, <token range of post dom node 1>, <token range of post dom 2> ...
//	 ...........................
//
// ]
// Here [] is used to specify list, they will not appear in test case
// For example
//
// <<<<<
// 80::174, 150,155, 4, 150,155, 160,172, -1,-1, -4,-4,
// 80::174, 160,172, 3, 160,172, -1,-1, -4,-4,
// 80::174, -1,-1, 1, -1,-1
// >>>>>
func TestPostDominator(t *testing.T) {
	testFolderName := "testdata/post-dominator"
	testFiles, err := util.GetAllFiles(testFolderName)
	if err != nil {
		t.Fatal(err)
	}

	for _, testFile := range testFiles {
		if filepath.Ext(testFile) != ".go" {
			continue
		}
		testFilePath, _ := filepath.Abs(testFile)
		packageList, err := util.LoadTestFile(testFile)
		if err != nil {
			t.Error(err)
		}
		if len(packageList) == 0 {
			t.Errorf("For file : %s, package informations not found\n", testFilePath)
		}
		pkg := packageList[0]
		astList := pkg.Syntax
		if len(astList) == 0 {
			t.Errorf("In file : %s, ast list found empty\n", testFilePath)
		}
		util.PopulatePkgInfo(packageList)
		// Load the current ast and parse the markers
		curAst := astList[0]
		fset := pkg.Fset

		// Find all the function declarations inside the test file.
		funcMap := make(map[string]ast.Node)
		allFunctions := util.GetAllFunctions(curAst, false)
		for _, function := range allFunctions {
			offsetStr := fmt.Sprintf("%d::%d", fset.Position(function.Pos()).Offset, fset.Position(function.End()).Offset)
			funcMap[offsetStr] = function
		}

		markerList, err := util.ParseMarkers(curAst, fset)
		if err != nil {
			t.Logf("In file : %s, %v\n", testFilePath, err)
			continue
		}
		if len(markerList) == 0 {
			t.Errorf("In file : %s, no marker is found", testFilePath)
			continue
		}

		for offsetStr := markerList.RemoveFirst(); offsetStr != ""; offsetStr = markerList.RemoveFirst() {
			var markerSb strings.Builder
			markerSb.WriteString(offsetStr)
			targetFunc := funcMap[offsetStr]
			// Assert matching function found
			if targetFunc == nil {
				t.Errorf("In file : %s, no function found with token range %s\n", testFilePath, offsetStr)
			}
			var fnBody *ast.BlockStmt
			switch fn := targetFunc.(type) {
			case *ast.FuncDecl:
				fnBody = fn.Body
			case *ast.FuncLit:
				fnBody = fn.Body
			default:
				t.Errorf("Selected node is not a FuncDecl or FuncLit\n")
				return
			}
			fg := CreateCFG(fnBody, fset)
			postDom := CreatePostDominator(fg)

			node := getFlowNodeFromMarker(&markerList, testFilePath, fg, curAst, fset, &markerSb)
			if node == nil {
				t.Errorf("Nil Node selected")
			}
			actualPostDominators := postDom.getPostDominator(node)
			if actualPostDominators == nil {
				t.Errorf("For file : %s, Post Dominators found nil\n", testFilePath)
			}
			markerStr := markerList.RemoveFirst()
			markerSb.WriteString("," + markerStr)
			postDominatorCount, err := strconv.Atoi(markerStr)
			if err != nil {
				t.Error(err)
			}

			expectedPostDominators := *set.New[IFlowNode]()
			for i := 0; i < postDominatorCount; i++ {
				expectedNode := getFlowNodeFromMarker(&markerList, testFilePath, fg, curAst, fset, &markerSb)
				expectedPostDominators.Add(expectedNode)
			}

			var actualPostDomSb strings.Builder
			for _, actualPostDominator := range actualPostDominators.Elements() {
				actualPostDomSb.WriteString(FlowNodeString(actualPostDominator, fset))
				actualPostDomSb.WriteString("#")
			}

			if len(expectedPostDominators.Elements()) != len(actualPostDominators.Elements()) {
				t.Errorf("In file %s, marker: %s, for node %s, post dominator count doesn't match match. Expected : %d,"+
					" Found : %d, \nActualSet: %s\n", testFilePath, markerSb.String(), FlowNodeString(node, fset),
					len(expectedPostDominators.Elements()), len(actualPostDominators.Elements()), actualPostDomSb.String())
			}

			for _, expectedPostDominator := range expectedPostDominators.Elements() {
				if !actualPostDominators.Contains(expectedPostDominator) {
					if flowNode, ok := expectedPostDominator.(FlowNode); ok {
						if _, ok := flowNode.Node.(*ast.ReturnStmt); ok {
							continue
						}
					}
					t.Errorf(
						"Expected post dominator not found in file: %s, marker: %s,  for node: %s expected post "+
							"dominator : %s, but actual post dominator set is :\n%s\n", testFilePath, markerSb.String(),
						FlowNodeString(node, fset), FlowNodeString(expectedPostDominator, fset), actualPostDomSb.String())
				}
			}
		}
	}
}
