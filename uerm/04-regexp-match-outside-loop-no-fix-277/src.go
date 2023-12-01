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
 * Contributors: Nayeem Hasan (OpenRefactory, Inc.)
 *******************************************************************************/

package taint

import (
	"fmt"
	"go/ast"
	"go/types"
	"net"
	"strconv"
	"strings"

	ap "github.com/OpenRefactory-Inc/icr-for-go/pointer/accesspath"
	"github.com/OpenRefactory-Inc/icr-for-go/pointer/constraint"
	"github.com/OpenRefactory-Inc/icr-for-go/pointer/data"
	"github.com/OpenRefactory-Inc/icr-for-go/util"
	"github.com/OpenRefactory-Inc/icr-for-go/util/deque"
	"github.com/OpenRefactory-Inc/icr-for-go/util/set"
	"github.com/fatih/camelcase"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/go/packages"
)

// sensitiveWords contains sensitive keywords which should not
// ne used in weak hashing algorithm.
var sensitiveWords = set.OfElemets(
	"password",
	"pwd",
	"pass",
	"passwd",
	"passwords",
	"certificate",
	"certificates",
	"cert",
	"credential",
	"credentials",
	"secret",
	"secrets",
	"ssl",
	"tls",
	"https",
	"key",
	"keys",
)

// StateMap contains the taint states for different sink type.
type StateMap map[SinkType]State

// IsEmpty checks if the taint state map is nil or empty
func (sm StateMap) IsEmpty() bool {
	return len(sm) == 0
}

// IsUnknown checks if all entries of the taint map is populated with unknown.
// For param and global locations we populate as unknown.
func (sm StateMap) IsUnknown() bool {
	for k, v := range sm {
		if k == WeakRandom || k == WeakHash || k == Ste || k == Sdl {
			// By default weak random ans weak hash is populated as not
			// tainted in API PopulateTaint, skip this.
			continue
		}
		if v != Unknown {
			return false
		}
	}
	return true
}

// Bundle contains all the data structures for taint analysis.
type Bundle struct {
	// Taints contains mapping between access path to a taint map.
	Taints map[ap.AccessPath]StateMap

	// RootTaintPath maps from an access path and to a set of access
	// paths of the taint sources from which the taint came.
	RootTaintPath map[ap.AccessPath]*set.Set[ap.AccessPath]

	// HiddenCmLinkMap maps from an access path and to a set of access
	// paths. This map is required for string concatenation, method invocation
	// where taint is propagated from one location to other without
	// linking the locations directly in the graph.
	HiddenCmLinkMap map[ap.AccessPath]*set.Set[ap.AccessPath]

	// Stores info of pending taints which has not been resolved yet.
	PendingTaints map[ap.AccessPath]PendingTaint

	// PropagationLog keeps track of all the changes associated with an
	// access path. The key is an access path and the value is a list of
	// chain members.
	PropagationLog PropagationLog
}

// NewBundle initializes a taint bundle.
func NewBundle() *Bundle {
	return &Bundle{
		Taints:          make(map[ap.AccessPath]StateMap),
		RootTaintPath:   make(map[ap.AccessPath]*set.Set[ap.AccessPath]),
		HiddenCmLinkMap: make(map[ap.AccessPath]*set.Set[ap.AccessPath]),
		PendingTaints:   make(map[ap.AccessPath]PendingTaint),
		PropagationLog:  make(PropagationLog),
	}
}

// Clears all the data structures in the taint bundle.
func (b *Bundle) Clear() {
	maps.Clear(b.Taints)
	maps.Clear(b.RootTaintPath)
	maps.Clear(b.PendingTaints)
	maps.Clear(b.PropagationLog)
	maps.Clear(b.HiddenCmLinkMap)
}

// Merge this bundle with another bundle.
func (b *Bundle) Merge(other *Bundle) {
	for path, taintMap := range other.Taints {
		b.AddToTaintsMap(path, taintMap)
	}

	for path, rootPaths := range other.RootTaintPath {
		b.RootTaintPath[path] = rootPaths
	}

	for path, missingPaths := range other.HiddenCmLinkMap {
		b.AddToHiddenCmLinkMap(path, missingPaths)
	}

	for path, chainList := range other.PendingTaints {
		for _, chain := range chainList {
			b.AddToPendingTaint(path, chain)
		}
	}

	for path, chainMembers := range other.PropagationLog {
		for _, cm := range chainMembers {
			b.PropagationLog.Add(path, cm)
		}
	}
}

// Clone this bundle.
func (b *Bundle) Clone() *Bundle {
	cloned := NewBundle()

	for path, taintMap := range b.Taints {
		clonedTaintMap := make(StateMap)
		for sink, state := range taintMap {
			clonedTaintMap[sink] = state
		}
		cloned.Taints[path] = clonedTaintMap
	}

	for path, rootPaths := range b.RootTaintPath {
		cloned.RootTaintPath[path] = rootPaths.Clone()
	}

	for path, chainLists := range b.PendingTaints {
		cloned.PendingTaints[path] = chainLists
	}

	b.PropagationLog.CopyTo(cloned.PropagationLog)

	for path, pathSet := range b.HiddenCmLinkMap {
		cloned.HiddenCmLinkMap[path] = pathSet.Clone()
	}

	return cloned
}

// CopyFrom creates a fresh copy from another bundle.
func (b *Bundle) CopyFrom(other *Bundle) {
	*b = *other.Clone()
}

// IsTainted checks if the location denoted by the path
// is tainted or not.
func (b *Bundle) IsTainted(path ap.AccessPath) bool {
	_, ok := b.Taints[path]
	return ok
}

// PopulateTaint populates a taint map with the given state.
func PopulateTaint(general, hardCoded State, isIpAddr bool) StateMap {
	taintMap := make(StateMap)
	for _, sink := range SinkList {
		if sink == Hcp || sink == Hck || sink == Hcs {
			taintMap[sink] = hardCoded
		} else if sink == Hci {
			taintMap[sink] = hardCoded
			if hardCoded == Tainted && !isIpAddr {
				taintMap[sink] = NotTainted
			}
		} else if sink == WeakRandom || sink == WeakHash || sink == Ste || sink == Sdl {
			taintMap[sink] = NotTainted
		} else {
			taintMap[sink] = general
		}
	}
	return taintMap
}

// PopulateTaint populates a taint map with the given state.
func PopulateTaintForSinks(srcForSinks []SinkType) StateMap {
	taintMap := make(StateMap)
	for _, sink := range SinkList {
		if slices.Contains(srcForSinks, sink) {
			taintMap[sink] = Tainted
		} else {
			taintMap[sink] = NotTainted
		}
	}
	return taintMap
}

// AddToPendingTaint adds a set of chain members in the PendingTaints map.
func (b *Bundle) AddToPendingTaint(path ap.AccessPath, chainMembers []ChainMember) {
	if len(chainMembers) == 0 {
		return
	}
	if pendingTaint, ok := b.PendingTaints[path]; ok {
		pendingTaint.AddChain(chainMembers)
	} else {
		pendingTaint = make(PendingTaint)
		pendingTaint.AddChain(chainMembers)
		b.PendingTaints[path] = pendingTaint
	}
}

// AddToHiddenCmLinkMap adds a set of access paths in the HiddenCmLinkMap map.
func (b *Bundle) AddToHiddenCmLinkMap(path ap.AccessPath, missingPaths *set.Set[ap.AccessPath]) {
	if missingPaths.IsEmpty() {
		return
	}
	if _, ok := b.HiddenCmLinkMap[path]; !ok {
		b.HiddenCmLinkMap[path] = set.New[ap.AccessPath]()
	}
	b.HiddenCmLinkMap[path].AddAll(missingPaths)
}

// AddToRootTaintPaths adds a set of access paths in the RootTaintPath map.
func (b *Bundle) AddToRootTaintPaths(path ap.AccessPath, rootPaths *set.Set[ap.AccessPath]) {
	if rootPaths.IsEmpty() {
		return
	}

	// Issue 261
	// Flatten the roots. For example:
	// Say the root paths contains the following entries
	// a* ---> *b, *c
	// *b ---> *b
	// *c ---> *c
	// Now, we are trying to add *p ---> *a
	// It will be flattended to *p ---> *b, *c
	flattenedRoots := set.New[ap.AccessPath]()
	seenPaths := set.New[ap.AccessPath]()
	worklist := deque.New[ap.AccessPath]()
	rootPaths.ForEach(worklist.AddLast)
	for !worklist.IsEmpty() {
		root, _ := worklist.RemoveFirst()
		if seenPaths.Contains(root) {
			continue
		}
		seenPaths.Add(root)
		if roots, ok := b.RootTaintPath[root]; ok {
			roots.ForEach(func(rt ap.AccessPath) {
				if rt == root {
					flattenedRoots.Add(rt)
				} else {
					worklist.AddLast(rt)
				}
			})
		} else {
			flattenedRoots.Add(root)
		}
	}

	if _, ok := b.RootTaintPath[path]; !ok {
		b.RootTaintPath[path] = set.New[ap.AccessPath]()
	}
	b.RootTaintPath[path].AddAll(flattenedRoots)
}

// AddToTaintsMap performs an OR operation between the passed taint map and
// the taint stored for the given access path. The result of the OR operation
// is stored in the Taints map against the given access path.
func (b *Bundle) AddToTaintsMap(path ap.AccessPath, taintMap StateMap) {
	if taintMap.IsEmpty() {
		return
	}
	if curTaintMap, ok := b.Taints[path]; ok {
		for sink, state := range taintMap {
			curTaintMap[sink] = curTaintMap[sink].Or(state)
		}
	} else {
		b.Taints[path] = taintMap
	}
}

// PopulateTaintForField populates taint for a selector expression
// if the given expression represents a taint source field.
func (b *Bundle) PopulateTaintForField(
	selExpr *ast.SelectorExpr, pkg *packages.Package, edges *set.Set[data.Edge]) {

	selType, ok := pkg.TypesInfo.Selections[selExpr]
	if !ok || selType.Kind() != types.FieldVal {
		return
	}
	FieldName := selExpr.Sel.Name
	qName := fmt.Sprintf("%s.%s", selType.Recv().String(), FieldName)
	srcForSinks, ok := taintedFieldMap[qName]
	if !ok {
		return
	}
	var taintMap StateMap
	if len(srcForSinks) == 0 {
		taintMap = PopulateTaint(Tainted, NotTainted, false)
	} else {
		taintMap = PopulateTaintForSinks(srcForSinks)
	}
	edges.ForEach(func(e data.Edge) {
		b.AddToTaintsMap(e.DestAccessPath, taintMap)
	})
}

// FlowTaint collects source and destination locations based on the taint passing
// info and calls flowTaintFromDestToSrc which flows taint from sources to destinations.
func (b *Bundle) FlowTaint(
	taintMethod TaintMethod,
	callExpr *ast.CallExpr,
	retLocs, recvAndArgLocs []*set.Set[data.Edge],
	nodeTr util.TokenRange,
	getChain func(ap.AccessPath, *set.Set[ap.AccessPath])) {
	srcLocs, destLocs := set.New[data.Edge](), set.New[data.Edge]()
	isExternalSrc := false
	for from, taintDest := range taintMethod.TaintMap {
		fromIdxList := from.Indexes()
		if len(fromIdxList) != 1 {
			// We do not have any case where taint is passing from multiple index location.
			// So, ignoring for now.
			continue
		}
		srcIdx := fromIdxList[0]
		switch {
		case srcIdx == -1000:
			// index for taint source is -1000
			isExternalSrc = true
		case srcIdx == 0:
			// 0 represents the calling context location
			srcLocs.AddAll(recvAndArgLocs[0])
		case srcIdx > 0 && srcIdx <= len(callExpr.Args):
			srcLocs.AddAll(recvAndArgLocs[srcIdx])
		case srcIdx >= 1000:
			// This reprsents the variadic argument. If the argument
			// position is n then the index in json file will be n *1000.
			pos := srcIdx / 1000
			for i := pos; i <= len(callExpr.Args); i++ {
				srcLocs.AddAll(recvAndArgLocs[i])
			}
		}
		for _, destIdx := range taintDest.To {
			switch {
			case destIdx < 0:
				if pos := -destIdx; pos <= len(retLocs) {
					destLocs.AddAll(retLocs[pos-1])
				}
			case destIdx == 0:
				destLocs.AddAll(recvAndArgLocs[0])
			case destIdx > 0 && destIdx <= len(callExpr.Args):
				destLocs.AddAll(recvAndArgLocs[destIdx])
			case destIdx >= 1000:
				if pos := destIdx / 1000; pos == len(callExpr.Args) {
					destLocs.AddAll(recvAndArgLocs[pos])
				}
			}
		}
		if isExternalSrc || !srcLocs.IsEmpty() {
			b.flowTaintFromSrcToDest(srcLocs, destLocs, nodeTr, taintMethod.SrcForSinks, getChain)
		}
		srcLocs.Clear()
		destLocs.Clear()
	}
}

// flowTaintFromSrcToDest flows taint info from the source locations to
// destinations. It also populates the necessary data structures of taint bundle.
func (b *Bundle) flowTaintFromSrcToDest(
	srcLocs, destLocs *set.Set[data.Edge],
	nodeTr util.TokenRange,
	srcForSinks []SinkType,
	getChain func(ap.AccessPath, *set.Set[ap.AccessPath])) {
	var taintMap StateMap
	var cm ChainMember
	rootPaths := set.New[ap.AccessPath]()
	missingLinks := set.New[ap.AccessPath]()
	if srcLocs == nil || srcLocs.IsEmpty() {
		if len(srcForSinks) == 0 {
			taintMap = PopulateTaint(Tainted, NotTainted, false)
		} else {
			taintMap = PopulateTaintForSinks(srcForSinks)
		}
		cm = ChainMember{
			NodeTr: nodeTr,
			Kind:   SourceExternal,
		}
	} else {
		cm = ChainMember{
			NodeTr: nodeTr,
			Kind:   PassThrough,
		}
		srcLocs.ForEach(func(e data.Edge) {
			missingLinks.Add(e.DestAccessPath)
			taintMap = OrTaintMap(taintMap, b.Taints[e.DestAccessPath], false)
			if roots, ok := b.RootTaintPath[e.DestAccessPath]; ok {
				rootPaths.AddAll(roots)
			}
		})
	}
	if taintMap.IsEmpty() {
		return
	}
	destLocs.ForEach(func(e data.Edge) {
		// Issue 126
		// Propagate taints to all the down stream paths for array and map.
		chain := set.New[ap.AccessPath]()
		getChain(e.DestAccessPath, chain)
		chain.ForEach(func(path ap.AccessPath) {
			b.AddToTaintsMap(path, taintMap)
			b.PropagationLog.Add(path, cm)
			b.AddToHiddenCmLinkMap(path, missingLinks)
			b.AddToRootTaintPaths(path, rootPaths)
		})
	})
}

// PopulateTaintForSensitiveData checks if certaint sensitive keywords exist in a variable
// name and if exist, populate taint for WeakHash and Sdl sink for the given locations.
func (b *Bundle) PopulateTaintForSensitiveData(varName string, edges *set.Set[data.Edge]) {
	if edges == nil {
		return
	}
	// Go uses camel case by convention
	for _, word := range camelcase.Split(varName) {
		if sensitiveWords.Contains(strings.ToLower(word)) {
			// Sensitive keyword exist in the variable name.
			// Populate taint for WeakHash
			taintMap := PopulateTaintForSinks([]SinkType{WeakHash, Sdl})
			edges.ForEach(func(e data.Edge) {
				b.AddToTaintsMap(e.DestAccessPath, taintMap)
			})
		}
	}
}

// SanitizeTaint sanitizes taint for the sanitizer types.
func (b *Bundle) SanitizeTaint(taintMethod TaintMethod, callExpr *ast.CallExpr,
	retLocs []*set.Set[data.Edge], recvAndArgLocs []*set.Set[data.Edge]) {
	sanitizedLocs := set.New[data.Edge]()
	for _, sanitizedIdx := range taintMethod.SanitizedIndexes {
		switch {
		case sanitizedIdx < 0:
			if pos := -sanitizedIdx; pos <= len(retLocs) {
				sanitizedLocs.AddAll(retLocs[pos-1])
			}
		case sanitizedIdx == 0:
			// 0 represents the calling context location
			sanitizedLocs.AddAll(recvAndArgLocs[0])
		case sanitizedIdx > 0 && sanitizedIdx <= len(callExpr.Args):
			sanitizedLocs.AddAll(recvAndArgLocs[sanitizedIdx])
		case sanitizedIdx >= 1000:
			// This reprsents the variadic argument. If the argument
			// position is n then the index in json file will be n *1000.
			pos := sanitizedIdx / 1000
			for i := pos; i <= len(callExpr.Args); i++ {
				sanitizedLocs.AddAll(recvAndArgLocs[i])
			}
		}
	}
	sanitizedLocs.ForEach(func(e data.Edge) {
		if existingTaint, ok := b.Taints[e.DestAccessPath]; ok {
			for _, sanitizerType := range taintMethod.SanitizerTypes {
				existingTaint[sanitizerType] = Sanitized
			}
		}
	})
}

// CheckTaint collects all the tainted locations for a sink and calls
// checkTaintAndPopulate where taint is checked.
func (b *Bundle) CheckTaint(info TaintMethod, callExpr *ast.CallExpr,
	recvAndArgLocs []*set.Set[data.Edge], nodeTr util.TokenRange, pkg *packages.Package) {
	for from, taintDest := range info.TaintMap {
		if len(taintDest.Sinks) == 0 {
			continue
		}
		var taintedLocsList []*set.Set[data.Edge]
		var taintedArgsPosList [][]int
		toIdx := taintDest.To[0]
		if toIdx > 0 {
			typ := pkg.TypesInfo.TypeOf(callExpr.Args[toIdx-1])
			if impls, ok := interfaceMap[info.ParamTypes[toIdx-1]]; ok {
				if !slices.Contains(impls, typ.String()) {
					continue
				}
			}
		}
		// Issue 194
		// Sinks are checked per index. For each index, we check the corresponding
		// sink list if there is any. Then for each sink, we check if it is tainted or not.
		// Sinks which are dependent on multiple index will be represented like this
		// "taint": {
		//   "1&0": {
		//     "sinks": [
		//       "WeakHash"
		//     ]
		//   }
		// }
		// This indicates that this method will be a sink for WeakHash if
		// both calling context location and location of 1st argument are tainted.
		for _, srcIdx := range from.Indexes() {
			taintedLocs := set.New[data.Edge]()
			var taintedArgsPos []int
			switch {
			case srcIdx == 0:
				// 0 represents the calling context location
				taintedLocs.AddAll(recvAndArgLocs[0])
				taintedArgsPos = append(taintedArgsPos, 0)
			case srcIdx > 0 && srcIdx <= len(callExpr.Args):
				taintedLocs.AddAll(recvAndArgLocs[srcIdx])
				taintedArgsPos = append(taintedArgsPos, srcIdx)
			case srcIdx >= 1000:
				// Reprsents the variadic argument.
				pos := srcIdx / 1000
				for i := pos; i <= len(callExpr.Args); i++ {
					taintedLocs.AddAll(recvAndArgLocs[i])
					taintedArgsPos = append(taintedArgsPos, i)
				}
			}
			if !taintedLocs.IsEmpty() {
				taintedLocsList = append(taintedLocsList, taintedLocs)
				taintedArgsPosList = append(taintedArgsPosList, taintedArgsPos)
			}
		}
		for _, sink := range taintDest.Sinks {
			if len(taintedLocsList) > 0 {
				b.checkTaintAndPopulate(taintedLocsList, taintedArgsPosList, sink, callExpr, nodeTr)
			}
		}
	}
}

// checkTaintAndPopulate checks if any location of the taintedLocs are tainted
// for the given sink. If it is found to be tainted, necessary info is populated
// which is used inside FT fixer.
// It also handles the case of pending taints.
func (b *Bundle) checkTaintAndPopulate(taintedLocsList []*set.Set[data.Edge], taintedArgsPosList [][]int, sink SinkType,
	callExpr *ast.CallExpr, nodeTr util.TokenRange) {
	pendingLocs := set.New[data.Edge]()
	cm := ChainMember{
		NodeTr:   nodeTr,
		Kind:     TaintSink,
		SinkType: sink,
	}
	var taintedArgIndices []*set.Set[int]
	// Check each location for taint.
	// If the taint is found, store the info in TaintInfoMap
	// which will be used inside FT refactoring.
	// For other cases, the location will be added in the
	// pending taint map.
	isTaintedLoc := true
	needToCheckPendingTaint := true
	var chaintAccessPath ap.AccessPath
	for listIdx, taintedLocs := range taintedLocsList {
		containsTaintedLoc := false
	Loop:
		for setIdx, taintedLoc := range taintedLocs.Elements() {
			isTainted := b.IsTaintedFor(taintedLoc.DestAccessPath, sink)
			switch isTainted {
			case util.True:
				if taintedLoc.Constraint == constraint.Sat {
					chaintAccessPath = taintedLoc.DestAccessPath
					containsTaintedLoc = true
					taintedArgIndices = append(taintedArgIndices, set.OfElemets(taintedArgsPosList[listIdx][setIdx]))
					break Loop
				} else if taintedLoc.Constraint != constraint.Unsat {
					pendingLocs.Add(taintedLoc)
				}
			case util.Maybe:
				if taintedLoc.Constraint != constraint.Unsat {
					pendingLocs.Add(taintedLoc)
				}
			case util.False:
				needToCheckPendingTaint = false
			}
		}
		if !containsTaintedLoc {
			isTaintedLoc = false
			break
		}
	}
	if isTaintedLoc {
		chainFragments := b.GetChainFragmentsFor(chaintAccessPath)
		chainFragments = append(chainFragments, cm)
		sortedChain := CmSorter(chainFragments).SortedMembers()
		AddToTaintInfoMap(nodeTr, sink, sortedChain, taintedArgIndices...)
	}

	if !needToCheckPendingTaint {
		return
	}
	pendingLocs.ForEach(func(e data.Edge) {
		targetPath := e.DestAccessPath
		if roots, ok := b.RootTaintPath[targetPath]; ok && !roots.IsEmpty() {
			chainFragments := b.GetChainFragmentsFor(targetPath)
			chainFragments = append(chainFragments, cm)
			sortedChain := CmSorter(chainFragments).SortedMembers()
			roots.ForEach(func(rootPath ap.AccessPath) {
				b.AddToPendingTaint(rootPath, sortedChain)
			})
		}
	})
}

// CollectHiddenLinks collects all the missing links for a location recursively.
func (b *Bundle) CollectHiddenLinks(loc ap.AccessPath, visited *set.Set[ap.AccessPath]) []ChainFragment {
	visited.Add(loc)
	var cmList []ChainFragment
	if links, ok := b.HiddenCmLinkMap[loc]; ok {
		for _, link := range links.Elements() {
			if visited.Contains(link) {
				continue
			}
			cmList = append(cmList, b.CollectHiddenLinks(link, visited)...)
			cmList = append(cmList, b.PropagationLog.Get(link)...)
		}
	}
	return cmList
}

// GetChainFragmentsFor gives a combined list of ChainFragments from
// both the propagation log and hidden links for the given path
func (b *Bundle) GetChainFragmentsFor(path ap.AccessPath) []ChainFragment {
	chainFragments := b.PropagationLog.Get(path)
	hiddenCms := b.CollectHiddenLinks(path, set.New[ap.AccessPath]())
	chainFragments = append(chainFragments, hiddenCms...)
	return chainFragments
}

// isTaintedFor Checks if a particular access path/location is tainted for a sink.
// If the location could not be identified as tainted, the root paths of the given
// location will be searched for taint for the given source.
// The result is calculated using the following truth table:
//
//	path | root = return
//	  T  |   X  =    T
//	  X  |   T  =    T
//	  MB |   F  =    MB
//	  F  |   MB =    MB
//	  F  |   F  =    F
//
// Here, X denotes any value.
func (b *Bundle) IsTaintedFor(loc ap.AccessPath, sink SinkType) util.TriBool {
	// Check taint of the given location
	if taintMap, ok := b.Taints[loc]; ok {
		if state, ok := taintMap[sink]; ok {
			switch state {
			case Tainted:
				return util.True
			case Sanitized:
				return util.False
			}
		}
	}
	return util.Maybe
}

// orTaintMap performs OR of two taint maps.
func OrTaintMap(t1, t2 StateMap, strConcat bool) StateMap {
	if t1.IsEmpty() {
		return t2
	}
	if t2.IsEmpty() {
		return t1
	}

	result := make(StateMap)

	for sink, state := range t1 {
		if strConcat && sink >= Hcp && sink <= Hci {
			result[sink] = state.And(t2[sink])
		} else {
			result[sink] = state.Or(t2[sink])
		}
	}
	return result
}

// IsHardCodedIp checks if the given string refers to a hardcoded ip address.
// This is used to decide whether taint for HCI sink will be generated for a string.
// Some valid IPs are excluded like:
// - Private IP like 192.168.x.x etc.
// - loopback IP like 127.0.0.1
// - Unspecified IP like 0.0.0.0
// - Broadcast IP (255.255.255.255)
func IsHardCodedIp(ipStr string) bool {
	if unquoted, err := strconv.Unquote(ipStr); err == nil {
		ipStr = unquoted
	}
	if strings.ContainsAny(ipStr, ":") {
		ipStr = strings.Split(ipStr, ":")[0]
	}
	ip := net.ParseIP(ipStr)
	return ip != nil &&
		!ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsUnspecified() &&
		!ip.Equal(net.IPv4bcast)
}
