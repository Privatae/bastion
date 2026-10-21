package main

// `service install` on Windows refuses a program outside Program Files
// (windowsServiceBinaryOK), because whoever can replace the service's file
// runs code as LocalSystem. Where Program Files IS must come from HKLM, which
// only an administrator can change, and never from %ProgramFiles%: an elevated
// process's environment carries the elevating account's own variables. That
// code is behind //go:build windows, so the suite reads it instead of running it.

import (
	"go/ast"
	"go/token"
	"strconv"
	"testing"
)

func TestTheServiceBinaryCheckTakesProgramFilesFromHKLM(t *testing.T) {
	p := parseSources(t)
	f, ok := p.files["sysservice_windows.go"]
	if !ok {
		t.Fatal("sysservice_windows.go is not in the package")
	}
	var fromEnv []string
	readsHKLM := false
	installUsesIt := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv") && len(x.Args) == 1 {
					if lit, ok := x.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, _ := strconv.Unquote(lit.Value); v == "ProgramFiles" {
							fromEnv = append(fromEnv, p.fset.Position(x.Pos()).String())
						}
					}
				}
			}
		case *ast.FuncDecl:
			switch x.Name.Name {
			case "programFilesDir":
				lm, name := false, false
				ast.Inspect(x, func(m ast.Node) bool {
					if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "LOCAL_MACHINE" {
						lm = true
					}
					if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, _ := strconv.Unquote(lit.Value); v == "ProgramFilesDir" {
							name = true
						}
					}
					return true
				})
				readsHKLM = lm && name
			case "installSystemService":
				ast.Inspect(x, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "programFilesDir" {
							installUsesIt = true
						}
					}
					return true
				})
			}
		}
		return true
	})
	if len(fromEnv) > 0 {
		t.Errorf("Program Files is read from the environment, which the elevating account can set: %v", fromEnv)
	}
	if !readsHKLM {
		t.Error("programFilesDir must read ProgramFilesDir under HKLM (registry.LOCAL_MACHINE)")
	}
	if !installUsesIt {
		t.Error("installSystemService must take Program Files from programFilesDir")
	}
}
