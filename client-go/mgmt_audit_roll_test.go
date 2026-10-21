package main

// The audit file's roll, checked on EVERY target — deliberately untagged.
//
// mgmt_audit_test.go carries `//go:build !windows` because it borrows setupBox
// and driveOp, so TestMgmtAuditRolls there is structurally incapable of seeing a
// Windows-only roll failure. It did not see one: the roll was called with the
// log file still open, which unix permits and Windows refuses outright, and the
// discarded error made the refusal silent (mgmtAuditRoll's comment has the full
// mechanism). Both tests below run on Windows — the first by not borrowing a
// unix fixture, the second by reading the source rather than running it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"testing"
)

// rollTestConfigHome points configDir() at a temp dir on whatever platform the
// test is running on. setupBox sets XDG_CONFIG_HOME, which is why it is
// unix-only; os.UserConfigDir reads a different variable per family (os/file.go,
// UserConfigDir), so a portable fixture has to set the one that is actually
// consulted.
func rollTestConfigHome(t *testing.T) {
	t.Helper()
	d := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("AppData", d)
	case "darwin", "ios":
		t.Setenv("HOME", d)
	case "plan9":
		t.Setenv("home", d)
	default:
		t.Setenv("XDG_CONFIG_HOME", d)
	}
}

// Past the cap the file moves aside and the live one starts again, with the
// writer holding no handle on it at the moment of the rename.
//
// Inflated with a truncate rather than 8 MiB of real records: the roll decides
// on st.Size() alone, nothing in this test reads the filler, and
// TestMgmtAuditRolls already covers that both halves stay valid JSONL. self is
// "" so pairingGrantSig returns without touching a pairing file — this test is
// about the roll, not about what a record contains.
func TestMgmtAuditRollsWithNoHandleHeldOpen(t *testing.T) {
	rollTestConfigHome(t)
	p, err := mgmtAuditPath()
	if err != nil {
		t.Fatal(err)
	}

	mgmtAudit("", "seed", "observe", auditAllowed, "", 0, nil, "")
	if err := os.Truncate(p, mgmtAuditMaxBytes); err != nil {
		t.Fatal(err)
	}

	mgmtAudit("", "uptime", "observe", auditAllowed, "", 0, nil, "")

	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("the file must roll aside once it passes the cap — on Windows this "+
			"is where an open handle on the source refuses the rename: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err == nil && st.Size() >= mgmtAuditMaxBytes {
		t.Fatalf("the live file must start again after a roll, got %d bytes — the "+
			"rename reported nothing and the cap is bounding nothing", st.Size())
	}
}

// THE SOURCE-LEVEL HALF, and the one that catches the regression on the machine
// tests are actually run on.
//
// The test above is the real behavioural gate, but only on Windows: on unix a
// rename with the handle still open succeeds, so reintroducing `defer
// fh.Close()` in mgmtAudit turns nothing red here. That is exactly how the
// original shipped. So this asserts the ORDER in the source — the file is closed
// before mgmtAuditRoll is called — which is checkable everywhere.
//
// mgmtAuditRoll's signature carries the other half: it takes a path and no
// *os.File, so it cannot be handed a live handle at all without a deliberate
// change the compiler would force you to make.
func TestMgmtAuditClosesTheFileBeforeRolling(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mgmt_audit.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "mgmtAudit" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("mgmtAudit not found in mgmt_audit.go — this check would pass vacuously")
	}

	closedAt, rolledAt := -1, -1
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.DeferStmt:
			if sel, ok := s.Call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
				t.Errorf("mgmt_audit.go:%d defers Close past the roll. On Windows "+
					"os.Rename needs DELETE access on the source and os.OpenFile's "+
					"share mode does not grant it, so the roll is refused, the error "+
					"is discarded, and the file grows without bound.",
					fset.Position(s.Pos()).Line)
			}
		case *ast.CallExpr:
			if sel, ok := s.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" && closedAt < 0 {
				closedAt = fset.Position(s.Pos()).Line
			}
			if id, ok := s.Fun.(*ast.Ident); ok && id.Name == "mgmtAuditRoll" {
				rolledAt = fset.Position(s.Pos()).Line
			}
		}
		return true
	})

	if rolledAt < 0 {
		t.Fatal("mgmtAudit no longer calls mgmtAuditRoll — the cap bounds nothing")
	}
	if closedAt < 0 {
		t.Fatal("mgmtAudit never closes the file it opened")
	}
	if closedAt > rolledAt {
		t.Errorf("mgmt_audit.go closes the file at line %d but rolls at line %d — "+
			"the roll must come after the close", closedAt, rolledAt)
	}
}
