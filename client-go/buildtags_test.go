package main

// buildtags_test.go — a test file that borrows a unix-only fixture must say so.
//
// WHY THIS EXISTS. Several test files here use helpers (setupBox, driveOp,
// withConfigDir, …) that live behind `//go:build !windows`. A new test file that
// calls one without carrying the same constraint breaks the WINDOWS test build
// with `undefined: setupBox`.
//
// The trap is which command notices. `GOOS=windows go build ./...` passes —
// build does not compile test files — so a cross-build check reports green
// while `GOOS=windows go vet ./...` is red. That mistake was made twice in this
// package in two days, both times by someone who had run the build and
// believed the target was covered. A comment in the file that needs the tag can
// only be read after it has been written, so this checks it instead.
//
// It is deliberately NOT tagged itself: it must run on the platform people
// actually run tests on, and it reads the tree from disk rather than being
// compiled into any particular target. It asks the TOOLCHAIN whether a file
// belongs in a Windows build (go/build's own MatchFile, which understands every
// constraint form and the _windows.go name suffix) rather than parsing
// constraints by hand.

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestATestFileBorrowingAUnixFixtureCarriesTheTag(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	win := build.Default
	win.GOOS = "windows"

	type fileInfo struct {
		name    string
		onWin   bool
		file    *ast.File
		fileSet *token.FileSet
	}
	var files []fileInfo
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, "_test.go") {
			continue
		}
		onWin, err := win.MatchFile(".", n)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		files = append(files, fileInfo{n, onWin, f, fset})
	}
	if len(files) == 0 {
		t.Fatal("no test files found — this check would pass vacuously")
	}

	// Every top-level name declared ONLY in files excluded from a Windows build.
	unixOnly := map[string]string{}
	for _, fi := range files {
		if fi.onWin {
			continue
		}
		for _, d := range fi.file.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil {
					unixOnly[decl.Name.Name] = fi.name
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						for _, id := range s.Names {
							unixOnly[id.Name] = fi.name
						}
					case *ast.TypeSpec:
						unixOnly[s.Name.Name] = fi.name
					}
				}
			}
		}
	}
	// A name also declared in a Windows-included file is not unix-only.
	for _, fi := range files {
		if !fi.onWin {
			continue
		}
		for _, d := range fi.file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil {
				delete(unixOnly, fn.Name.Name)
			}
		}
	}

	for _, fi := range files {
		if !fi.onWin {
			continue
		}
		ast.Inspect(fi.file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || id.Obj != nil { // id.Obj set = declared in this file
				return true
			}
			if from, bad := unixOnly[id.Name]; bad {
				t.Errorf("%s:%d uses %s, which is declared in %s behind a "+
					"constraint that excludes Windows. Add this as line 1 of %s:\n"+
					"\t//go:build !windows\n"+
					"Caught here because `GOOS=windows go build ./...` does NOT compile "+
					"test files and would report green; `GOOS=windows go vet ./...` is "+
					"what sees it.",
					fi.name, fi.fileSet.Position(id.Pos()).Line, id.Name, from, fi.name)
				return false
			}
			return true
		})
	}
}
