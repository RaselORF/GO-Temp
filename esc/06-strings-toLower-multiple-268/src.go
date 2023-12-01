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

package refactoring

import (
	"fmt"
	"go/ast"
	"log"
	"strings"

	"github.com/OpenRefactory-Inc/icr-for-go/pointer/taint"
	"github.com/OpenRefactory-Inc/icr-for-go/util"
	"github.com/OpenRefactory-Inc/icr-for-go/util/set"
	"github.com/dave/dst"
)

// # FT (Fix Taint Refactoring)
//
// Several fixers for detecting various kind of injection attack,
// hard-coded secrets etc.
type FTRefactoring struct {
	*RefactoringData
}

func (FTRefactoring) DoCheckInitialConditions() error {
	return nil
}

func (fr FTRefactoring) DoTransform() {
	taintInfos := taint.TaintInfoMap[fr.FilePath]
	for _, taintInfo := range taintInfos {
		node := util.GetAstNodeFromTokenRange(taintInfo.NodeTr)
		_, ok := node.(*ast.ExprStmt)
		fmt.Print(ok)
		if node == nil {
			continue
		}
		fr.TargetNode = node
		sink := taintInfo.SinkType
		trace := taintInfo.GenerateTrace(sink)
		var sb strings.Builder
		sb.WriteString(orPrefix)
		switch sink {
		case taint.Sql:
			sb.WriteString(warningForSql)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-1")
		case taint.Os:
			sb.WriteString(warningForOs)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-2")
		case taint.Xss:
			sb.WriteString(warningForXss)
			sb.WriteString(trace)
			if !fr.generateXssFix(node, taintInfo.TaintedArgIndices, &sb) {
				generateWarningDiff(fr, sb.String(), "FT-3")
			}
		case taint.Path:
			sb.WriteString(warningForPath)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-4")
		case taint.Ssrf:
			sb.WriteString(warningForSsrf)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-5")
		case taint.Log:
			sb.WriteString(warningForLog)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-6")
		case taint.Ste:
			sb.WriteString(warningForSte)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-7")
		case taint.Xpath:
			sb.WriteString(warningForXpath)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-8")
		case taint.Desrl:
			sb.WriteString(warningForDesrl)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-9")
		case taint.Hci:
			sb.WriteString(warningForHci)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-10")
		case taint.Hck:
			sb.WriteString(warningForHck)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-11")
		case taint.Hcp:
			sb.WriteString(warningForHcp)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-12")
		case taint.Hcs:
			sb.WriteString(warningForHcs)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-20")
		case taint.Or:
			sb.WriteString(warningForOr)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-13")
		case taint.WeakRandom:
			sb.WriteString(warningForWeakRandom)
			generateWarningDiff(fr, sb.String(), "FT-14")
		case taint.Sdl:
			sb.WriteString(warningForSdl)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-15")
		case taint.WeakHash:
			sb.WriteString(warningForWeakHash)
			generateWarningDiff(fr, sb.String(), "FT-16")
		case taint.Session:
			sb.WriteString(warningForSession)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-17")
		case taint.Zip:
			sb.WriteString(warningForZip)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-18")
		case taint.Email:
			sb.WriteString(warningForEmail)
			sb.WriteString(trace)
			generateWarningDiff(fr, sb.String(), "FT-19")
		}
	}
}

func (FTRefactoring) GetName() string {
	return "Fix Taint"
}

func (FTRefactoring) GetShortName() string {
	return "FT"
}

// generateXssFix will add the bluemonday sanitization code before the call expression
// Returns true if the fix is generated, else returns false.
func (fr FTRefactoring) generateXssFix(node ast.Node, argIndexArr []*set.Set[int], sb *strings.Builder) bool {
	// get callExpr from node
	exprStmt, ok := node.(*ast.ExprStmt)
	if ok {
		node = exprStmt.X
	}
	callExpr, ok := node.(*ast.CallExpr)
	if !ok {
		return false
	}
	// Get argPos, which arg has to be replaced.
	// Assumes only one arg is tainted here
	var argPos int = -1
	for _, argIndexSet := range argIndexArr {
		if argIndexSet.Contains(0) || len(argIndexSet.Elements()) > 1 {
			continue
		}
		argPos = argIndexSet.Elements()[0]
		break
	}
	if argPos == -1 {
		return false
	}
	// Get argType from the matcher
	// Here argPos can be > matcherParam length for variadic parameter. If then take the
	// param type of last index
	var argType string
	if typ := fr.Pkg.TypesInfo.TypeOf(callExpr.Args[argPos-1]); typ != nil {
		argType = typ.String()
	}
	argStr, err := util.GetNodeStr(callExpr.Args[argPos-1], fr.Pkg.Fset)
	if err != nil {
		return false
	}
	// Select appropriate bluemonday method depending on param type
	var sanitizeMethodIdentDst *dst.Ident
	switch argType {
	case "[]byte":
		sanitizeMethodIdentDst = dst.NewIdent("SanitizeBytes")
	case "string", "[]string":
		sanitizeMethodIdentDst = dst.NewIdent("Sanitize")
	case "io.Reader", "*strings.Reader":
		sanitizeMethodIdentDst = dst.NewIdent("SanitizeReader")
	default:
		return false
	}
	// Check if import of bluemonday is already in import list, and get the import name
	db, err := getDstBundle(fr.Pkg.Fset, fr.AST)
	if err != nil {
		log.Println(err)
		return false
	}
	importName := "bluemonday"
	blueMondayImportSpec := getImportSpecWithName(fr.AST, "github.com/microcosm-cc/bluemonday")
	if blueMondayImportSpec != nil {
		if blueMondayImportSpec.Name != nil {
			importName = blueMondayImportSpec.Name.Name
		}
	} else if addImport(fr.AST, db.Decorator, "github.com/microcosm-cc/bluemonday", "") != nil {
		return false
	}
	// If import name is . then we will generate code UGCPolicy().Sanitize(param)
	// Otherwise will generate code importName.UGCPolicy().Sanitize(param)
	var sanitizeMethodSelectorDst dst.Expr
	if importName == "." {
		sanitizeMethodSelectorDst = dst.NewIdent("UGCPolicy")
	} else {
		sanitizeMethodSelectorDst = &dst.SelectorExpr{
			X:   dst.NewIdent(importName),
			Sel: dst.NewIdent("UGCPolicy"),
		}
	}
	// Generate dst from
	// io.WriteString(w, param) to
	// io.WriteString(w, bluemonday.UGCPolicy().Sanitize(param))
	blueMondaySanitizedArg := &dst.CallExpr{
		Args: []dst.Expr{
			dst.NewIdent(argStr),
		},
		Fun: &dst.SelectorExpr{
			X: &dst.CallExpr{
				Args: []dst.Expr{},
				Fun:  sanitizeMethodSelectorDst,
			},
			Sel: sanitizeMethodIdentDst,
		},
	}
	// change callExpr's arg with new arg
	decNode, ok := db.Decorator.Map.Dst.Nodes[callExpr]
	if !ok {
		return false
	}
	callExprDec, ok := decNode.(*dst.CallExpr)
	if !ok {
		return false
	}
	callExprDec.Args[argPos-1] = blueMondaySanitizedArg
	sb.WriteString("// Fix: iCR sanitizes the tainted input.")
	generateWarning(fr, db.Decorator, sb.String())
	generateDiff(fr, db.Dst, db.DstStr, "Xss")
	return true
}
