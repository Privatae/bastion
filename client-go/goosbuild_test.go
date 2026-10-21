package main

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// EVERY PLATFORM FUNCTION EXISTS ON EVERY TARGET THAT BUILDS THIS PACKAGE.
//
// A function with one file per platform (contextPeerUID in contextsock_linux.go
// and contextsock_darwin.go) and a caller in a file every unix builds
// (contextsock_unix.go) leaves any other unix with an undefined name, and
// nothing in CI cross-builds one: `GOOS=freebsd go build` failed that way.
// The release targets are linux, darwin and windows (deploy/build.sh);
// freebsd and openbsd are not released, but they build, with what has no
// implementation there refusing (contextsock_other.go and the other
// *_other.go files).
//
// This asks the toolchain which files each target compiles (go/build's
// MatchFile) and checks that every package function called from those files
// is declared in them. It is not a type check, and it does not compile; it
// catches the missing-platform-file mistake, which is the one that happened,
// on the platform the tests already run on.
func TestEveryCalledPlatformFunctionIsDeclaredOnEveryTarget(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	type parsed struct {
		name string
		file *ast.File
	}
	var files []parsed
	declaredAnywhere := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		files = append(files, parsed{n, f})
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				declaredAnywhere[fd.Name.Name] = true
			}
		}
	}
	if len(files) < 50 {
		t.Fatalf("parsed only %d files; is the test running in the package directory?", len(files))
	}
	for _, goos := range []string{"linux", "darwin", "windows", "freebsd", "openbsd"} {
		ctx := build.Default
		ctx.GOOS = goos
		ctx.CgoEnabled = false
		declared := map[string]bool{}
		var matched []parsed
		for _, p := range files {
			ok, err := ctx.MatchFile(".", p.name)
			if err != nil {
				t.Fatalf("%s: %v", p.name, err)
			}
			if !ok {
				continue
			}
			matched = append(matched, p)
			for _, d := range p.file.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
					declared[fd.Name.Name] = true
				}
			}
		}
		missing := map[string]string{}
		for _, p := range matched {
			ast.Inspect(p.file, func(x ast.Node) bool {
				c, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := c.Fun.(*ast.Ident); ok && declaredAnywhere[id.Name] && !declared[id.Name] {
					missing[id.Name] = p.name
				}
				return true
			})
		}
		var out []string
		for fn, where := range missing {
			out = append(out, fn+" (called in "+where+")")
		}
		sort.Strings(out)
		if len(out) > 0 {
			t.Errorf("GOOS=%s: called but not declared for this target: %s", goos, strings.Join(out, ", "))
		}
	}
}
