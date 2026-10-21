package main

// console_test.go — every child process this daemon starts on Windows must be
// started with no console window.
//
// WHY A SOURCE-LEVEL TEST. The defect is invisible on the platform the tests run
// on: on Linux there is no console to allocate, so a behavioural test of
// hideConsole passes vacuously here and the real thing can only be seen by a
// person looking at a Windows desktop. What CAN be checked anywhere is the
// property that actually matters — that no exec site was left out. The last
// one was found by watching two blue windows flash every ten minutes
// (console_windows.go); this is what stops the next shell-out doing it again.
//
// It asks the toolchain which files are in a Windows build (go/build's own
// MatchFile, as buildtags_test.go does) rather than reading name suffixes, so a
// file behind any constraint form is judged correctly.

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// exemptFromHideConsole: files whose exec sites are deliberately different.
var exemptFromHideConsole = map[string]string{
	// The self-update relaunch MUST keep DETACHED_PROCESS — that flag is the
	// whole point, it is what lets the replacement outlive the process being
	// replaced. It has no console by construction and starts nothing visible.
	"relaunch_windows.go": "sets DETACHED_PROCESS deliberately",
	// The approvals popup starts Edge itself: a GUI program with no console to
	// hide, where hideConsole's HideWindow (SW_HIDE in the start-up info) would
	// ask Edge to open its first window hidden — the popup, invisible. Its one
	// exec site is the Edge launch; the browser fallback goes through
	// openBrowser, which hides rundll32's console as every other site does.
	"uipopup_windows.go": "starts a GUI window that must be seen",
}

// isExecCommand reports whether a call is exec.Command or exec.CommandContext.
func isExecCommand(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "exec" {
		return false
	}
	return sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext"
}

// SCOPE, because a guard is only as wide as its walk:
// this reads THIS directory only. The bastion is a single-package module today
// — `go list ./...` is one package — so that is every exec site there is. The
// day a subpackage appears, its shell-outs are invisible here and this check
// goes on passing while the thing it protects stops being true. Widen the walk
// then; do not assume the walk widened itself.
func TestEveryWindowsExecSiteHidesItsConsole(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	win := build.Default
	win.GOOS = "windows"

	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if _, skip := exemptFromHideConsole[name]; skip {
			continue
		}
		onWin, err := win.MatchFile(".", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !onWin {
			continue // never compiled for Windows; there is no window to hide
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		// One top-level declaration at a time, so a `var x = func(){…}` (as
		// observe_ops.go uses) is one scope and the name match stays local.
		for _, decl := range f.Decls {
			var bound []struct {
				name string
				line int
			}
			hidden := map[string]bool{}

			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.AssignStmt:
					// x := exec.Command(…)  — the shape that CAN be hidden.
					if len(node.Rhs) == 1 && len(node.Lhs) >= 1 {
						if call, ok := node.Rhs[0].(*ast.CallExpr); ok && isExecCommand(call) {
							if id, ok := node.Lhs[0].(*ast.Ident); ok {
								bound = append(bound, struct {
									name string
									line int
								}{id.Name, fset.Position(node.Pos()).Line})
							}
						}
					}
				case *ast.CallExpr:
					// hideConsole(x)
					if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "hideConsole" {
						if len(node.Args) == 1 {
							if arg, ok := node.Args[0].(*ast.Ident); ok {
								hidden[arg.Name] = true
							}
						}
					}
					// exec.Command(…).Output() — nothing is bound, so nothing
					// can be hidden. Must be split into a variable first.
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
						if inner, ok := sel.X.(*ast.CallExpr); ok && isExecCommand(inner) {
							t.Errorf("%s:%d — exec.Command(…).%s() is started inline, so no "+
								"hideConsole can be applied and it opens a console window on "+
								"Windows. Assign it first:\n"+
								"\tcmd := exec.CommandContext(…)\n\thideConsole(cmd)\n\t… cmd.%s()",
								name, fset.Position(node.Pos()).Line, sel.Sel.Name, sel.Sel.Name)
						}
					}
				}
				return true
			})

			for _, b := range bound {
				checked++
				if !hidden[b.name] {
					t.Errorf("%s:%d — %s is an exec.Cmd that is never passed to hideConsole, "+
						"so on Windows it opens a console window on the user's desktop every "+
						"time it runs. Add `hideConsole(%s)` before it is started (and AFTER "+
						"any assignment to %s.SysProcAttr, which would otherwise replace the "+
						"flags). See console_windows.go.",
						name, b.line, b.name, b.name, b.name)
				}
			}
		}
	}

	// A guard that checked nothing would pass for ever after a refactor moved
	// every exec site behind a helper this walk does not recognise.
	if checked < 8 {
		t.Fatalf("only %d exec site(s) examined — this check has stopped finding them, "+
			"which makes it a green light that proves nothing", checked)
	}
}
