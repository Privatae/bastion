package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// PinnedKeys reads the productionReleaseKeys list out of a bastion source
// file (client-go/release_sign.go) by parsing it as Go, so the publish and
// verify scripts see exactly the keys the compiler does: comments are not
// keys, and the list's layout does not matter.
func PinnedKeys(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var found *ast.CompositeLit
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.VAR {
			continue
		}
		for _, sp := range g.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, n := range vs.Names {
				if n.Name != "productionReleaseKeys" || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					return nil, errors.New("productionReleaseKeys is not a list literal")
				}
				found = lit
			}
		}
	}
	if found == nil {
		return nil, fmt.Errorf("%s declares no productionReleaseKeys", path)
	}
	var keys []string
	for _, e := range found.Elts {
		b, ok := e.(*ast.BasicLit)
		if !ok || b.Kind != token.STRING {
			return nil, errors.New("productionReleaseKeys holds something other than string literals")
		}
		k, err := strconv.Unquote(b.Value)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}
