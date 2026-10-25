package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseTreeArgs(t *testing.T) {
	if _, _, err := parseTreeArgs(nil); err == nil {
		t.Fatal("a pid is required")
	}
	for _, bad := range []string{"0", "1", "-5", "abc", "12 ; rm -rf /", ""} {
		if _, _, err := parseTreeArgs([]string{bad}); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	pid, n, err := parseTreeArgs([]string{" 4242 "})
	if err != nil || pid != 4242 || n != treeDefaultMaxNodes {
		t.Fatalf("defaults: %d %d %v", pid, n, err)
	}
	if _, n, _ := parseTreeArgs([]string{"7", "99999"}); n != treeMaxNodes {
		t.Fatalf("the cap is capped: %d", n)
	}
	if treeDefaultMaxNodes != 500 || treeMaxNodes != 800 {
		t.Fatalf("caps must match the host side: %d / %d", treeDefaultMaxNodes, treeMaxNodes)
	}
	if _, _, err := parseTreeArgs([]string{"7", "x"}); err == nil {
		t.Fatal("a non-integer cap is refused")
	}
	// the only channel into a helper is the environment, as two integers
	env := helperEnv(4242, 300)
	if len(env) != 2 || env[0] != "PRIVATAE_TARGET_PID=4242" || env[1] != "PRIVATAE_MAX_NODES=300" {
		t.Fatalf("helper env: %v", env)
	}
}

func TestBoundTreeRecountsAndCaps(t *testing.T) {
	leaf := func(name string) *computerNode { return &computerNode{Role: "button", Name: name} }
	win := &computerNode{Role: "window", Name: "Fusion 360", Children: []*computerNode{
		{Role: "toolbar", Children: []*computerNode{leaf("Sketch"), leaf("Extrude"), leaf("Revolve")}},
		leaf("Close"),
	}}
	out, count, trunc := boundTree([]*computerNode{win}, 100)
	if count != 6 || trunc || len(out) != 1 || len(out[0].Children) != 2 || len(out[0].Children[0].Children) != 3 {
		t.Fatalf("full tree: count=%d trunc=%v %+v", count, trunc, out)
	}
	// the cap holds on THIS side even if a helper lied about truncation
	_, count, trunc = boundTree([]*computerNode{win}, 3)
	if count != 3 || !trunc {
		t.Fatalf("capped: count=%d trunc=%v", count, trunc)
	}
	// long strings are cut so a page-long label cannot fill the reply
	long := &computerNode{Role: "text", Name: strings.Repeat("n", 500), ID: strings.Repeat("i", 500), Value: strings.Repeat("v", 500)}
	out, _, _ = boundTree([]*computerNode{long}, 10)
	rc := utf8.RuneCountInString
	if rc(out[0].Name) > treeMaxText+1 || rc(out[0].ID) > treeMaxText+1 || rc(out[0].Value) > treeMaxText+1 {
		t.Fatalf("text caps: %d %d %d", rc(out[0].Name), rc(out[0].ID), rc(out[0].Value))
	}
	// the cut lands on a character boundary, never inside a multibyte one
	if got := cutRunes(strings.Repeat("é", 200), 5); got != "ééééé…" || !utf8.ValidString(got) {
		t.Fatalf("rune-safe cut: %q", got)
	}
	// a cycle-shaped depth bomb is cut at treeMaxDepth
	deep := &computerNode{Role: "group"}
	cur := deep
	for i := 0; i < 60; i++ {
		next := &computerNode{Role: "group"}
		cur.Children = []*computerNode{next}
		cur = next
	}
	_, count, trunc = boundTree([]*computerNode{deep}, 1000)
	if !trunc || count != treeMaxDepth+1 {
		t.Fatalf("depth cap: count=%d trunc=%v", count, trunc)
	}
}

func TestTreeReportShape(t *testing.T) {
	// a bad argument is reported with no pid, which the handler turns into exit 2
	rep := computerTreeReport([]string{"nope"})
	if rep.Supported || rep.PID != 0 || rep.Reason == "" {
		t.Fatalf("bad arg: %+v", rep)
	}
	b, _ := json.Marshal(treeReport{Platform: "linux", Scan: computerTreeKind, Supported: true, PID: 7,
		Windows:   []*computerNode{{Role: "window", Name: "x", Children: []*computerNode{{Role: "button", Name: "OK", Focused: true}}}},
		NodeCount: 2})
	s := string(b)
	for _, want := range []string{`"supported":true`, `"node_count":2`, `"focused":true`, `"role":"button"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("report missing %s: %s", want, s)
		}
	}
	if strings.Contains(s, `"truncated"`) || strings.Contains(s, `"offscreen"`) {
		t.Fatalf("false flags are omitted: %s", s)
	}
}

func TestHelperTreeDecodes(t *testing.T) {
	raw := `{"app":"Fusion360","truncated":false,"windows":[{"role":"window","name":"flowerpot v3","x":10,"y":20,"w":800,"h":600,"enabled":true,
	  "children":[{"role":"button","name":"Revolve","id":"cmdRevolve","enabled":true},{"role":"edit","name":"Angle","value":"360"}]}]}`
	var ht helperTree
	if err := json.Unmarshal([]byte(raw), &ht); err != nil {
		t.Fatal(err)
	}
	out, count, _ := boundTree(ht.Windows, 100)
	if ht.App != "Fusion360" || count != 3 || out[0].Children[1].Value != "360" || out[0].Children[0].ID != "cmdRevolve" {
		t.Fatalf("%+v", out[0])
	}
	if out[0].Enabled == nil || !*out[0].Enabled {
		t.Fatal("enabled travels as a tri-state")
	}
}

func TestTreeOpInVocabulary(t *testing.T) {
	found := false
	for _, v := range mgmtOpVocabulary() {
		if v == "computer:tree" {
			found = true
		}
	}
	if !found || handlerOps["computer:tree"].root != rootNone {
		t.Fatal("computer:tree must be a rootNone handler in the vocabulary")
	}
}
