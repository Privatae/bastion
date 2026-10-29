package main

// Source-level checks behind the README's security model. Each one reads the
// package's own non-test sources, for every platform at once (build tags are
// not applied), and compares what it finds with a table written here. A new
// listener, route, program or write in one of these places fails the test
// until the table is changed with it, which is the point: the change then
// arrives with a reviewer looking at the claim it touches.
//
// The behaviour behind the same claims (what a listener refuses, what an op
// runs) is driven in claims_unix_test.go and beside each lane's own tests.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// srcPkg is the package's non-test sources, parsed once per test.
type srcPkg struct {
	fset  *token.FileSet
	files map[string]*ast.File // base name -> file
	funcs map[string]*ast.FuncDecl
	// methods maps a method name to every receiver type that declares it.
	methods map[string][]string
}

func parseSources(t *testing.T) *srcPkg {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	p := &srcPkg{fset: token.NewFileSet(), files: map[string]*ast.File{},
		funcs: map[string]*ast.FuncDecl{}, methods: map[string][]string{}}
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		p.addFile(n, f)
	}
	if len(p.files) < 50 {
		t.Fatalf("parsed only %d source files — is the test running in the package directory?", len(p.files))
	}
	return p
}

// addFile registers one parsed file and its functions. A test that proves a
// check can fail adds a synthetic file through here, so it is indexed exactly
// as a real one would be.
func (p *srcPkg) addFile(n string, f *ast.File) {
	p.files[n] = f
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		key := funcKey(fd)
		// The same name in two platform files (processIsRoot, …) is kept
		// once per file so neither body is lost to the other.
		if _, dup := p.funcs[key]; dup {
			key = key + "@" + n
		}
		p.funcs[key] = fd
		if fd.Recv != nil {
			p.methods[fd.Name.Name] = append(p.methods[fd.Name.Name], key)
		}
	}
}

// funcKeysIn is the p.funcs key of every function declared in file n.
func (p *srcPkg) funcKeysIn(n string) []string {
	var out []string
	for _, d := range p.files[n].Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		key := funcKey(fd)
		if p.funcs[key] != fd {
			key = key + "@" + n
		}
		out = append(out, key)
	}
	return out
}

// funcKey is "name" for a function and "Type.name" for a method.
func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if s, ok := typ.(*ast.StarExpr); ok {
		typ = s.X
	}
	if g, ok := typ.(*ast.IndexExpr); ok {
		typ = g.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// eachCall visits every call in the package with the file and the name of the
// function it sits in ("" at package level).
func (p *srcPkg) eachCall(visit func(file, fn string, call *ast.CallExpr)) {
	names := make([]string, 0, len(p.files))
	for n := range p.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, d := range p.files[n].Decls {
			fn := ""
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = funcKey(fd)
			}
			ast.Inspect(d, func(x ast.Node) bool {
				if c, ok := x.(*ast.CallExpr); ok {
					visit(n, fn, c)
				}
				return true
			})
		}
	}
}

// selName returns (receiver text, selector) for a call like a.b.C(…).
func selName(c *ast.CallExpr) (string, string) {
	s, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	return exprText(s.X), s.Sel.Name
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprText(v.Fun) + "()"
	case *ast.StarExpr:
		return "*" + exprText(v.X)
	case *ast.ParenExpr:
		return exprText(v.X)
	case *ast.CompositeLit:
		return exprText(v.Type) + "{}"
	case *ast.UnaryExpr:
		return v.Op.String() + exprText(v.X)
	case *ast.BasicLit:
		return v.Value
	case *ast.IndexExpr:
		return exprText(v.X) + "[" + exprText(v.Index) + "]"
	case *ast.SliceExpr:
		return exprText(v.X) + "[:]"
	}
	return "?"
}

// stringLits returns every string literal inside e, unquoted.
func stringLits(e ast.Node) []string {
	var out []string
	ast.Inspect(e, func(x ast.Node) bool {
		if b, ok := x.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// netstackParams names, per function, the parameters typed *netstack.Net: the
// tunnel's own network stack. A listener opened on one of them is a listener
// inside the tunnel.
func (p *srcPkg) netstackParams() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for key, fd := range p.funcs {
		for _, f := range fd.Type.Params.List {
			st, ok := f.Type.(*ast.StarExpr)
			if !ok || exprText(st.X) != "netstack.Net" {
				continue
			}
			for _, n := range f.Names {
				if out[key] == nil {
					out[key] = map[string]bool{}
				}
				out[key][n.Name] = true
			}
		}
	}
	return out
}

// listenSelectors are the calls that open something that accepts: a socket
// listener, a packet socket, or a server that makes its own listener.
var listenSelectors = map[string]bool{
	"Listen": true, "ListenTCP": true, "ListenUDP": true, "ListenPacket": true,
	"ListenUnix": true, "ListenUnixgram": true, "ListenIP": true, "ListenMulticastUDP": true,
	"ListenAndServe": true, "ListenAndServeTLS": true,
	"ListenTCPAddrPort": true, "ListenUDPAddrPort": true, "ListenPing": true,
	"CreateNamedPipe": true,
}

type listenSite struct {
	file, fn, call string
	lits           []string
}

func (p *srcPkg) listenSites() []listenSite {
	var out []listenSite
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		recv, sel := selName(c)
		if !listenSelectors[sel] {
			return
		}
		var lits []string
		for _, a := range c.Args {
			lits = append(lits, stringLits(a)...)
		}
		out = append(out, listenSite{file: file, fn: fn, call: recv + "." + sel, lits: lits})
	})
	return out
}

// Inside the tunnel, only gated listeners. Every listener opened on the
// tunnel's network stack is one of the four gated forwards, the stack itself
// is created in one place, and the only other thing done with it is dialling
// out to the host. A fifth listener, or the stack handed to any other
// function, fails here.
func TestOnlyTheGatedForwardsListenInsideTheTunnel(t *testing.T) {
	p := parseSources(t)
	params := p.netstackParams()

	want := map[string]bool{
		"run.go:serveOllamaForward":           true, // :11434, inference family
		"run.go:serveLLMForward":              true, // :18080, inference family
		"pii.go:servePIIForward":              true, // :18081, inference family
		"service.go:serveServiceForwards":     true, // :18100-18199, services family + reach grant
		"coder_forward.go:serveCoderForwards": true, // :18200-18299, mode:coder, owner's tunnel address only
	}
	got := map[string]bool{}
	sites := map[string]int{}
	for _, s := range p.listenSites() {
		recv := strings.SplitN(s.call, ".", 2)[0]
		if params[s.fn][recv] {
			got[s.file+":"+s.fn] = true
			sites[s.file+":"+s.fn]++
		}
	}
	for k, n := range sites {
		if n != 1 {
			t.Errorf("%s has %d call sites that listen on the tunnel's stack; each gated forward has one (serveServiceForwards' one site opens a listener per slot)", k, n)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s opens a listener on the tunnel's stack; every tunnel listener must be a gated forward listed here", k)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("%s no longer listens on the tunnel's stack — update this table and the README with it", k)
		}
	}

	// Only those four functions (and runPairing, which builds the stack) may
	// hold it at all.
	holders := map[string]bool{}
	for fn := range params {
		holders[fn] = true
	}
	for _, fn := range []string{"serveOllamaForward", "serveLLMForward", "servePIIForward", "serveServiceForwards", "serveCoderForwards"} {
		delete(holders, fn)
	}
	for fn := range holders {
		t.Errorf("%s takes the tunnel's network stack as a parameter; only the gated forwards may", fn)
	}
	var creators []string
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		if recv, sel := selName(c); recv == "netstack" && sel == "CreateNetTUN" {
			creators = append(creators, file+":"+fn)
		}
	})
	if len(creators) != 1 || creators[0] != "run.go:runPairing" {
		t.Fatalf("the tunnel's stack must be created in runPairing alone, found %v", creators)
	}

	// In runPairing the stack is passed to the four forwards and otherwise
	// used only to dial the host.
	rp := p.funcs["runPairing"]
	passedTo := map[string]bool{}
	ast.Inspect(rp.Body, func(x ast.Node) bool {
		switch v := x.(type) {
		case *ast.CallExpr:
			for _, a := range v.Args {
				if id, ok := a.(*ast.Ident); ok && id.Name == "tnet" {
					passedTo[exprText(v.Fun)] = true
				}
			}
			if recv, sel := selName(v); recv == "tnet" && sel != "DialContext" {
				t.Errorf("runPairing calls tnet.%s; the stack is only dialled out of", sel)
			}
		case *ast.AssignStmt:
			for _, r := range v.Rhs {
				if id, ok := r.(*ast.Ident); ok && id.Name == "tnet" {
					t.Errorf("runPairing copies the tunnel's stack into another variable")
				}
			}
		}
		return true
	})
	for fn := range passedTo {
		switch fn {
		case "serveOllamaForward", "serveLLMForward", "servePIIForward", "serveServiceForwards", "serveCoderForwards":
		default:
			t.Errorf("runPairing hands the tunnel's stack to %s", fn)
		}
	}

	// The ports: the README names them, the heartbeat reports them.
	if coderPortBase != 18200 || coderPortMax != 18299 {
		t.Errorf("coder tunnel ports moved: %d-%d", coderPortBase, coderPortMax)
	}
	if llmForwardPort != 18080 || piiForwardPort != 18081 || servicePortBase != 18100 || servicePortMax != 18199 {
		t.Errorf("tunnel ports moved: llm %d, pii %d, service %d-%d", llmForwardPort, piiForwardPort, servicePortBase, servicePortMax)
	}
}

// The bastion dials out. Every listener this package opens on the machine's
// own interfaces is in this table, with what it binds and how many call sites
// open it. (The WireGuard device's own UDP socket is opened inside the
// wireguard module, outside this package, and is the tunnel's outbound
// transport: it is not in this table.) Loopback literals are checked in the
// source; the per-pairing addresses are checked where they are allocated
// (TestListenAddressesAreOnlyEverAllocatedOnLoopback); the memory-mirror
// forwarder's two binds and its source check are TestMirrorPeerAllowed's.
func TestEveryListenerThisPackageOpensIsInTheTable(t *testing.T) {
	p := parseSources(t)
	params := p.netstackParams()

	type rule struct {
		prefix string // the network literal, when the call names one ("" = none required)
		sites  int    // call sites in that function; a second one is a second listener
		why    string
	}
	want := map[string]rule{
		"run.go:runPairing:net.Listen":         {"tcp", 1, "git proxy on cfg.GitProxyAddr (loopback, allocated by nextGitProxyAddr)"},
		"run.go:runPairing:srv.ListenAndServe": {"", 1, "local control port on cfg.ListenAddr (loopback, allocated by nextListenAddr)"},
		// The same two for a pairing with a Host on this machine (no tunnel).
		"run.go:runUnixPairing:net.Listen":                 {"tcp", 1, "git proxy on cfg.GitProxyAddr (loopback, allocated by nextGitProxyAddr)"},
		"run.go:runUnixPairing:srv.ListenAndServe":         {"", 1, "local control port on cfg.ListenAddr (loopback, allocated by nextListenAddr)"},
		"ui.go:startUIServer:net.Listen":                   {"", 1, "the console, 127.0.0.1 only"},
		"contextui.go:cmdContextUI:net.Listen":             {"", 1, "the context page, 127.0.0.1 only"},
		"service_mirror.go:mirrorPushBridge:net.Listen":    {"", 1, "the mirror push bridge, 127.0.0.1:0"},
		"mirror.go:serveMirrorForward:net.Listen":          {"", 1, "memory-mirror forwarder: loopback and the replica network's gateway, source-checked"},
		"contextsock_unix.go:contextSockListen:net.Listen": {"unix", 1, "a unix socket file, not a network port"},
		"ops_action_linux.go:opActionProbeUnit:net.Listen": {"tcp", 1, "the action-op probe, 127.0.0.1:0, open while one probe unit dials it"},
		"coders_linux.go:coderListenUnix:net.Listen":       {"unix", 1, "a coder run's egress.sock, a unix socket file in its run dir, not a network port"},
		"coders_other.go:coderListenUnix:net.Listen":       {"unix", 1, "the same, off Linux (coder mode refuses there)"},
		// Beside a Windows system service: the tray's own approvals window,
		// and the service's approvals pipe (approvalpipe.go), which takes no
		// remote client (PIPE_REJECT_REMOTE_CLIENTS) and, by its ACL, only
		// interactive users; TestTheApprovalPipeTakesLocalInteractiveClientsOnly.
		"tray_pipe_windows.go:startTrayPage:net.Listen":                             {"tcp", 1, "the tray's approvals window, 127.0.0.1 only"},
		"approvalpipe_windows.go:approvalPipeServer.create:windows.CreateNamedPipe": {"", 1, "the approvals pipe, a local named pipe, not a network port"},
	}
	loopbackOnly := map[string]bool{
		"ui.go:startUIServer:net.Listen":                   true,
		"contextui.go:cmdContextUI:net.Listen":             true,
		"tray_pipe_windows.go:startTrayPage:net.Listen":    true,
		"service_mirror.go:mirrorPushBridge:net.Listen":    true,
		"ops_action_linux.go:opActionProbeUnit:net.Listen": true,
	}
	seen := map[string]int{}
	for _, s := range p.listenSites() {
		recv := strings.SplitN(s.call, ".", 2)[0]
		if params[s.fn][recv] {
			continue // inside the tunnel: TestOnlyTheGatedForwardsListenInsideTheTunnel
		}
		key := s.file + ":" + s.fn + ":" + s.call
		seen[key]++
		r, ok := want[key]
		if !ok {
			t.Errorf("%s opens a listener that is not in this table (literals %q). A new listener must bind loopback; add it here with what it binds", key, s.lits)
			continue
		}
		if r.prefix != "" && (len(s.lits) == 0 || s.lits[0] != r.prefix) {
			t.Errorf("%s: want network %q, got %q", key, r.prefix, s.lits)
		}
		if loopbackOnly[key] {
			found := false
			for _, l := range s.lits {
				switch {
				case loopbackLiteral(l):
					found = true
				case l == "tcp" || l == "tcp4" || l == "tcp6":
				default:
					t.Errorf("%s binds %q; it must bind loopback", key, l)
				}
			}
			if !found {
				t.Errorf("%s: no loopback address in the bind (%q)", key, s.lits)
			}
		}
	}
	for k, r := range want {
		if seen[k] == 0 {
			t.Errorf("%s is in the table but no longer listens; take it out", k)
		} else if seen[k] != r.sites {
			t.Errorf("%s opens a listener at %d call sites, the table says %d; each one is a listener to account for", k, seen[k], r.sites)
		}
	}

	// The mirror forwarder binds exactly two addresses: the gateway it was
	// given and loopback.
	var mirrorAddrs []string
	ast.Inspect(p.funcs["serveMirrorForward"].Body, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if recv, sel := selName(c); recv == "net" && sel == "JoinHostPort" {
				mirrorAddrs = append(mirrorAddrs, exprText(c.Args[0]))
			}
		}
		return true
	})
	sort.Strings(mirrorAddrs)
	if strings.Join(mirrorAddrs, ",") != `"127.0.0.1",gw` {
		t.Errorf("the mirror forwarder must bind the replica gateway and loopback only, binds %v", mirrorAddrs)
	}
}

// loopbackLiteral reports whether a string literal in a bind names loopback:
// a host:port on 127.0.0.1 or [::1], or the bare host handed to JoinHostPort.
func loopbackLiteral(l string) bool {
	return l == "127.0.0.1" || l == "::1" || strings.HasPrefix(l, "127.0.0.1:") || strings.HasPrefix(l, "[::1]:")
}

// The control and git ports are whatever the pairing file says, so the
// claim rests on what writes those fields: the allocators, and a re-pair
// that keeps the old value. Nothing else in the code may set them.
func TestListenAddressesAreOnlyEverAllocatedOnLoopback(t *testing.T) {
	p := parseSources(t)
	allowed := map[string]bool{
		"nextListenAddr()":      true,
		"nextGitProxyAddr()":    true,
		"existing.ListenAddr":   true,
		"existing.GitProxyAddr": true,
		"cfg.GitProxyAddr":      true, // run.go writes the allocated value back to disk
	}
	for name, f := range p.files {
		ast.Inspect(f, func(x ast.Node) bool {
			check := func(field string, rhs ast.Expr) {
				if field != "ListenAddr" && field != "GitProxyAddr" {
					return
				}
				if !allowed[exprText(rhs)] {
					t.Errorf("%s sets %s from %s; only the loopback allocators may", name, field, exprText(rhs))
				}
			}
			switch v := x.(type) {
			case *ast.CompositeLit:
				if exprText(v.Type) != "Config" && exprText(v.Type) != "&Config" {
					return true
				}
				for _, e := range v.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if k, ok := kv.Key.(*ast.Ident); ok {
							check(k.Name, kv.Value)
						}
					}
				}
			case *ast.AssignStmt:
				for i, l := range v.Lhs {
					if s, ok := l.(*ast.SelectorExpr); ok && i < len(v.Rhs) {
						check(s.Sel.Name, v.Rhs[i])
					}
				}
			}
			return true
		})
	}

	// And the allocators hand out loopback, however many pairings exist.
	var cfgs []*Config
	for i := 0; i < 40; i++ {
		c := &Config{ListenAddr: nextListenAddr(cfgs)}
		c.GitProxyAddr = nextGitProxyAddr(append(cfgs, c))
		for _, a := range []string{c.ListenAddr, c.GitProxyAddr} {
			if !strings.HasPrefix(a, "127.0.0.1:") {
				t.Fatalf("allocated %q; every local port must be on 127.0.0.1", a)
			}
		}
		cfgs = append(cfgs, c)
	}
}

// No MCP endpoint: the bastion never speaks the protocol. Every HTTP route
// the binary registers, on any listener, is in this table; none of them, and
// no op name on the management lane, names MCP; no string in the code is a
// URL or route with an /mcp path, or speaks JSON-RPC, the protocol MCP is
// carried on; and no dependency is an MCP library.
//
// WHAT CHANGED, AND WHY THE GUARANTEE DID NOT. This test used to refuse any
// string containing "/mcp" at all. The connection-config reader
// (mcpconfig.go) has to name the files agent clients declare their tool
// servers in — .cursor/mcp.json, claude_desktop_config.json, an mcpServers
// key — and READING A FILE SPEAKS NO PROTOCOL. So the check now targets the
// protocol instead of the word (mcpReaderViolations):
//
//   - no literal anywhere is a URL or route with an mcp path segment;
//   - the config basenames and keys may appear in mcpconfig.go and nowhere
//     else, so a second file that starts reading (or writing) them is a
//     change a reviewer sees here;
//   - nothing declared in a config-reader file (mcpconfig*.go) imports, or
//     can reach through this package's call graph, net.Dial or net.Listen,
//     net/http, os/exec, TLS dialling or the websocket client. The reader is
//     handed its process list by agents.go; it starts and dials nothing.
//
// TestMCPReaderCheckCatchesADialAndAStrayBasename proves each of those can
// fail.
func TestNoRouteOpOrDependencySpeaksMCP(t *testing.T) {
	p := parseSources(t)
	// A route served by more than one surface names each file, "a.go|b.go":
	// the tray's page (uitray.go) answers a few of the console's own paths.
	want := map[string]string{
		// run.go: the loopback control port, one per pairing.
		"/healthz": "run.go", "/git-credential": "run.go", "/dcn/propose": "run.go",
		// The local console (ui*.go), loopback only.
		"/assets/": "ui.go", "/auth/ticket": "ui.go", "/signout": "ui.go",
		"/fragments/status": "ui.go", "/given": "ui.go", "/given/switch": "ui.go",
		"/fragments/given": "ui.go", "/approve": "ui.go|uitray.go", "/deny": "ui.go|uitray.go", "/": "ui.go",
		"/agents": "uisanction.go", "/fragments/agents": "uisanction.go",
		"/agents/mark": "uisanction.go", "/agents/unmark": "uisanction.go",
		"/fragments/context": "uicontext.go", "/context/scan": "uicontext.go",
		"/context/stop": "uicontext.go", "/context/ask": "uicontext.go",
		"/policy": "uipolicy.go", "/fragments/policy": "uipolicy.go",
		"/approvals": "uidevice.go|uitray.go", "/fragments/approvals": "uidevice.go|uitray.go",
		"/fragments/approvals-news": "uidevice.go|uitray.go", "/device/approve": "uidevice.go",
		"/device/deny": "uidevice.go", "/device/approve-shown": "uidevice.go",
		"/diskmap": "uidiskmap.go", "/fragments/diskmap": "uidiskmap.go",
		"/diskmap/scan": "uidiskmap.go", "/diskmap/stop": "uidiskmap.go",
		"/setup": "uisetup.go", "/setup/pair": "uisetup.go",
		"/setup/stepup/start": "uisetup.go", "/setup/stepup/qr": "uisetup.go",
		"/setup/stepup/key": "uisetup.go", "/setup/stepup/confirm": "uisetup.go",
		"/setup/folder/check": "uisetup.go", "/setup/folder/propose": "uisetup.go",
		"/setup/anchor/choose": "uisetup.go", "/setup/owner/name": "uisetup.go",
	}
	got := map[string]bool{}
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		_, sel := selName(c)
		if sel != "HandleFunc" && sel != "Handle" || len(c.Args) != 2 {
			return
		}
		lits := stringLits(c.Args[0])
		if len(lits) != 1 {
			t.Errorf("%s:%s registers a route that is not a string literal (%s); every route must be readable here", file, fn, exprText(c.Args[0]))
			return
		}
		route := lits[0]
		got[route] = true
		if f, ok := want[route]; !ok {
			t.Errorf("%s:%s registers %q, which is not in this table", file, fn, route)
		} else if !strings.Contains("|"+f+"|", "|"+file+"|") && route != "/" {
			t.Errorf("%q is registered in %s, the table says %s", route, file, f)
		}
		if strings.Contains(strings.ToLower(route), "mcp") {
			t.Errorf("%s:%s registers an MCP route %q", file, fn, route)
		}
	})
	for r := range want {
		if !got[r] {
			t.Errorf("%q is in the table but no longer registered; take it out", r)
		}
	}

	for _, v := range mcpReaderViolations(p) {
		t.Error(v)
	}
	for name, f := range p.files {
		for _, imp := range f.Imports {
			if strings.Contains(strings.ToLower(imp.Path.Value), "mcp") {
				t.Errorf("%s imports %s", name, imp.Path.Value)
			}
		}
	}
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(mod)), "mcp") {
		t.Errorf("go.mod names an MCP module:\n%s", mod)
	}
	for _, op := range mgmtOpVocabulary() {
		if strings.Contains(strings.ToLower(op), "mcp") {
			t.Errorf("the management lane answers an op named %q", op)
		}
	}
}

// mcpConfigNames are the file basenames and keys agent clients declare tool
// servers under. Only mcpconfig.go may name them. settings.json and
// config.toml are left out on purpose: many programs use those names (the
// coder lane reads the NVIDIA runtime's config.toml), so they say nothing
// about tool servers; the keys beside them do.
var mcpConfigNames = []string{"claude_desktop_config", "mcp.json", "mcp_config.json", ".claude.json",
	"mcpservers", "context_servers", "mcp_servers",
	// The clients' own directories, which name a settings.json or
	// config.toml as surely as the basename would.
	".cursor", ".codex", ".zed", ".codeium", ".vscode"}

// mcpURLOrRoute reports whether a string literal is a URL or route that
// addresses an mcp path. Outside a URL, every "/mcp" counts (/mcp, /mcp/x,
// /mcp-proxy) except a client's config FILE name: /mcp.json and
// /mcp_config.json.
func mcpURLOrRoute(l string) bool {
	l = strings.ToLower(l)
	if i := strings.Index(l, "://"); i >= 0 {
		rest := l[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return strings.Contains(rest[j:], "/mcp")
		}
		return false
	}
	for i := 0; ; {
		j := strings.Index(l[i:], "/mcp")
		if j < 0 {
			return false
		}
		rest := l[i+j+len("/mcp"):]
		if !strings.HasPrefix(rest, ".json") && !strings.HasPrefix(rest, "_config.json") {
			return true
		}
		i += j + len("/mcp")
	}
}

// mcpReaderSink: a package-level function or type that opens a connection,
// resolves a name, or starts a process — named as a call or as a value.
func mcpReaderSink(recv, sel string) bool {
	switch {
	case recv == "net" && (strings.HasPrefix(sel, "Dial") || strings.HasPrefix(sel, "Listen") ||
		strings.HasPrefix(sel, "Lookup") || strings.HasPrefix(sel, "Resolve") || sel == "Dialer" || sel == "Resolver"):
		return true
	case strings.Contains(recv, "net.Dialer") || strings.Contains(recv, "net.Resolver"):
		return true
	case recv == "http" || recv == "exec" || recv == "websocket" || recv == "rpc" || recv == "jsonrpc":
		return true
	case recv == "tls" && strings.HasPrefix(sel, "Dial"):
		return true
	case (recv == "os" || recv == "syscall" || recv == "unix" || recv == "windows") &&
		(sel == "StartProcess" || sel == "ForkExec" || sel == "Exec" || strings.HasPrefix(sel, "CreateProcess") ||
			strings.HasPrefix(sel, "ShellExecute") || sel == "WinExec"):
		return true
	case (recv == "syscall" || recv == "unix" || recv == "windows") && (sel == "Socket" || sel == "Connect" || sel == "Bind" ||
		sel == "Listen" || sel == "Sendto" || sel == "Sendmsg" || sel == "SendmsgN" || strings.HasPrefix(sel, "WSA") ||
		sel == "ConnectEx" || sel == "GetAddrInfoW" || sel == "GetHostByName" || strings.HasPrefix(sel, "DnsQuery")):
		return true
	case (recv == "syscall" || recv == "windows") && (strings.HasPrefix(sel, "LoadLibrary") || sel == "LoadDLL" ||
		sel == "MustLoadDLL" || sel == "NewLazyDLL" || sel == "NewLazySystemDLL"):
		// A DLL loaded by name reaches any function in it, past every check here.
		return true
	case recv == "registry" && sel == "OpenRemoteKey":
		return true
	}
	return false
}

// mcpReaderMethodSink: a METHOD call that connects, resolves or starts,
// whatever the receiver is called — d.Dial on a net.Dialer variable,
// c.Get on an http.Client, cmd.Run on an exec.Cmd. Over-approximate on
// purpose: it only applies to code the reader can reach.
var mcpReaderMethodSink = map[string]bool{"Dial": true, "DialContext": true, "DialTCP": true, "DialUDP": true,
	"DialUnix": true, "DialIP": true, "Listen": true, "ListenPacket": true, "LookupHost": true, "LookupIP": true,
	"LookupIPAddr": true, "LookupAddr": true, "LookupNetIP": true, "Do": true, "Get": true, "Post": true,
	"PostForm": true, "Head": true, "RoundTrip": true, "Start": true, "Run": true, "Output": true,
	"CombinedOutput": true, "Connect": true}

// mcpReaderAllowedImports is every package a config-reader file may import:
// parsing, strings, and opening files. Anything else is a change a reviewer
// has to see here first. x/sys/windows and its registry package are the
// Windows open (CreateFile and the handle's own type, attributes and owner)
// and the profile list it checks owners against; each can also start a
// process, open a socket, load a DLL or open a remote registry, and those
// calls are sinks in mcpReaderSink like their unix equivalents.
var mcpReaderAllowedImports = map[string]bool{"bytes": true, "encoding/json": true, "errors": true, "io": true,
	"io/fs": true, "net": true, "net/url": true, "os": true, "path/filepath": true, "regexp": true,
	"runtime": true, "sort": true, "strconv": true, "strings": true, "syscall": true, "unicode": true,
	"unicode/utf8": true, "golang.org/x/sys/unix": true, "golang.org/x/sys/windows": true,
	"golang.org/x/sys/windows/registry": true}

// mcpValueSink: a sink named as a VALUE rather than called (f := net.Dial).
// The http, exec and websocket packages also export constants and types
// (http.StatusOK, websocket.BinaryMessage), which name no connection; only
// their functions count here.
func mcpValueSink(recv, sel string) bool {
	switch recv {
	case "http", "exec", "websocket", "rpc", "jsonrpc":
		switch sel {
		case "Get", "Post", "Head", "PostForm", "Command", "CommandContext", "Dial", "DialContext",
			"DialHTTP", "DefaultClient", "DefaultDialer", "DefaultTransport", "NewClient":
			return true
		}
		return false
	}
	return mcpReaderSink(recv, sel)
}

// mcpSinksIn lists the network and process calls inside one declaration.
func mcpSinksIn(n ast.Node) []string {
	var out []string
	called := map[*ast.SelectorExpr]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		if c, ok := x.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				called[sel] = true
			}
		}
		return true
	})
	ast.Inspect(n, func(x ast.Node) bool {
		switch v := x.(type) {
		case *ast.SelectorExpr:
			recv := exprText(v.X)
			if (called[v] && mcpReaderSink(recv, v.Sel.Name)) || (!called[v] && mcpValueSink(recv, v.Sel.Name)) {
				out = append(out, recv+"."+v.Sel.Name)
			}
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && mcpReaderMethodSink[sel.Sel.Name] {
				out = append(out, exprText(sel.X)+"."+sel.Sel.Name+"()")
			}
		}
		return true
	})
	return out
}

// mcpReaderViolations is every way the package breaks the guarantee above.
func mcpReaderViolations(p *srcPkg) []string {
	var out []string
	names := make([]string, 0, len(p.files))
	for n := range p.files {
		names = append(names, n)
	}
	sort.Strings(names)
	var readerFiles []string
	for _, name := range names {
		if strings.HasPrefix(name, "mcpconfig") {
			readerFiles = append(readerFiles, name)
		}
		for _, s := range stringLits(p.files[name]) {
			l := strings.ToLower(s)
			if mcpURLOrRoute(s) || strings.Contains(l, "jsonrpc") || strings.Contains(l, "tools/call") {
				out = append(out, fmt.Sprintf("%s carries %q: nothing in the bastion addresses an MCP endpoint or speaks JSON-RPC", name, s))
			}
			// The protocol's namespace. The reader may name the npm scope
			// its reference servers are published under, to recognise one
			// running; nothing else may name it at all.
			if strings.Contains(l, "modelcontextprotocol") && !(name == "mcpconfig.go" && l == "@modelcontextprotocol/") {
				out = append(out, fmt.Sprintf("%s carries %q: only the config reader may name the reference servers' npm scope", name, s))
			}
			if name == "mcpconfig.go" {
				continue
			}
			for _, b := range mcpConfigNames {
				if strings.Contains(l, b) {
					out = append(out, fmt.Sprintf("%s names %q (%s): only mcpconfig.go reads agent clients' tool-server config", name, s, b))
				}
			}
		}
	}
	if len(readerFiles) == 0 {
		return append(out, "no mcpconfig*.go file: the reader moved, so this check is no longer checking it")
	}
	var roots []string
	for _, name := range readerFiles {
		for _, imp := range p.files[name].Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if !mcpReaderAllowedImports[path] {
				out = append(out, fmt.Sprintf("%s imports %s: the config reader reads files and nothing else", name, path))
			}
		}
		roots = append(roots, p.funcKeysIn(name)...)
	}
	// Package-level variables are nodes too ("var:name"): a function held in
	// one (var f = net.Dial, var g = func() { ... }) is reached by whoever
	// reads the variable, and a reader file's own variables are roots, since
	// their initialisers run with the package.
	g := p.callGraph()
	vars := map[string][]ast.Expr{}
	for _, name := range names {
		for _, d := range p.files[name].Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for _, id := range vs.Names {
					key := "var:" + id.Name
					vars[key] = append(vars[key], vs.Values...)
					if strings.HasPrefix(name, "mcpconfig") {
						roots = append(roots, key)
					}
				}
			}
		}
	}
	refs := func(n ast.Node) []string {
		var out []string
		ast.Inspect(n, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok {
				if _, isVar := vars["var:"+id.Name]; isVar {
					out = append(out, "var:"+id.Name)
				}
				if _, isFn := p.funcs[id.Name]; isFn {
					out = append(out, id.Name)
				}
			}
			return true
		})
		return out
	}
	sinks := map[string][]string{}
	for key, fd := range p.funcs {
		g[key] = append(g[key], refs(fd)...)
		if s := mcpSinksIn(fd); len(s) > 0 {
			sinks[key] = s
		}
	}
	for key, vals := range vars {
		for _, v := range vals {
			g[key] = append(g[key], refs(v)...)
			sinks[key] = append(sinks[key], mcpSinksIn(v)...)
		}
	}
	seen := reach(g, roots, nil)
	for fn, path := range seen {
		if what := sinks[fn]; len(what) > 0 {
			out = append(out, fmt.Sprintf("the config reader can reach %s, which reaches a network or process call (%s): %s",
				fn, strings.Join(what, ", "), path))
		}
	}
	sort.Strings(out)
	return out
}

// THE CHECK ABOVE CAN FAIL. A reader that starts a process, imports a
// network package, reaches a dialler through another function, or a second
// file that names a client's config file or an /mcp URL: each one is added
// as a synthetic source and must be reported. The real tree must report
// nothing, and the scan must have found sinks and roots to compare, so a
// broken extraction cannot pass by finding nothing.
func TestMCPReaderCheckCatchesADialAndAStrayBasename(t *testing.T) {
	clean := parseSources(t)
	if v := mcpReaderViolations(clean); len(v) != 0 {
		t.Fatalf("the real tree must be clean: %v", v)
	}
	if len(clean.funcKeysIn("mcpconfig.go")) < 10 {
		t.Fatal("found almost no functions in mcpconfig.go; the root extraction is broken")
	}
	add := func(p *srcPkg, name, src string) {
		t.Helper()
		f, err := parser.ParseFile(p.fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		p.addFile(name, f)
	}
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"the reader execs", "can reach mcpSneakRun", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakRun() { _ = exec.Command(\"x\") }\n"}},
		{"the reader dials through a helper elsewhere", "can reach sneakDialHelper", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakCall() { sneakDialHelper() }\n",
			"sneak_helper.go":    "package main\nfunc sneakDialHelper() { net.Dial(\"tcp\", \"x\") }\n"}},
		{"the reader imports net/http", "imports net/http", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport _ \"net/http\"\n"}},
		{"another file names a config file", "only mcpconfig.go reads", map[string]string{
			"sneak_other.go": "package main\nvar sneakPath = \".cursor/mcp.json\"\n"}},
		{"another file names the servers key", "only mcpconfig.go reads", map[string]string{
			"sneak_other.go": "package main\nvar sneakKey = \"mcpServers\"\n"}},
		{"a URL with an mcp path", "addresses an MCP endpoint", map[string]string{
			"sneak_other.go": "package main\nvar sneakURL = \"https://h.example.com/v1/mcp\"\n"}},
		{"a route", "addresses an MCP endpoint", map[string]string{
			"sneak_other.go": "package main\nvar sneakRoute = \"/mcp\"\n"}},
		{"a route with a suffix", "addresses an MCP endpoint", map[string]string{
			"sneak_other.go": "package main\nvar sneakRoute = \"/mcp-proxy\"\n"}},
		{"the reader dials through a Dialer variable", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakD() { var d net.Dialer; d.Dial(\"tcp\", \"x\") }\n"}},
		{"the reader dials through a function value", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakF() { f := net.Dial; f(\"tcp\", \"x\") }\n"}},
		{"the reader dials from a package-level function literal", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nvar mcpSneakV = func() { net.Dial(\"tcp\", \"x\") }\n"}},
		{"the reader opens a raw socket", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakS() { syscall.Socket(2, 1, 0) }\n"}},
		{"the reader resolves a name", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakL() { net.LookupHost(\"x\") }\n"}},
		{"the reader imports a websocket client not on a deny list", "imports golang.org/x/net/websocket", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport ws \"golang.org/x/net/websocket\"\nfunc mcpSneakW() { ws.Dial(\"x\", \"\", \"y\") }\n"}},
		{"the reader calls a dialler held in another file's variable", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nfunc mcpSneakH() { sneakDialer(\"tcp\", \"x\") }\n",
			"sneak_helper.go":    "package main\nvar sneakDialer = net.Dial\n"}},
		{"another file names a client's config directory", "only mcpconfig.go reads", map[string]string{
			"sneak_other.go": "package main\nvar sneakDir = \".codex/\"\n"}},
		{"the Windows reader starts a process", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport \"golang.org/x/sys/windows\"\nfunc mcpSneakCP() { windows.CreateProcess(nil, nil, nil, nil, false, 0, nil, nil, nil, nil) }\n"}},
		{"the Windows reader opens a socket", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport \"golang.org/x/sys/windows\"\nfunc mcpSneakWS() { windows.WSASocket(2, 1, 0, nil, 0, 0) }\n"}},
		{"the Windows reader loads a DLL by name", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport \"golang.org/x/sys/windows\"\nvar mcpSneakDLL = windows.NewLazySystemDLL(\"ws2_32.dll\")\n"}},
		{"the Windows reader opens a remote registry", "reaches a network or process call", map[string]string{
			"mcpconfig_sneak.go": "package main\nimport \"golang.org/x/sys/windows/registry\"\nfunc mcpSneakRR() { registry.OpenRemoteKey(\"h\", registry.LOCAL_MACHINE) }\n"}},
	}
	for _, c := range cases {
		p := parseSources(t)
		for n, src := range c.files {
			add(p, n, src)
		}
		found := false
		for _, v := range mcpReaderViolations(p) {
			if strings.Contains(v, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: not reported (want %q in %v)", c.name, c.want, mcpReaderViolations(p))
		}
	}
	// A config file name is not a URL path, and a file in the reader may
	// name one.
	for _, ok := range []string{".cursor/mcp.json", "mcp_config.json", ".codeium/windsurf/mcp_config.json", "managed-mcp.json"} {
		if mcpURLOrRoute(ok) {
			t.Errorf("%q read as an MCP URL or route", ok)
		}
	}
}

// callGraph maps each function to what it calls or refers to, by name.
// A method call through a value is resolved to every method of that name in
// the package, so the graph over-approximates: a path it cannot rule out is
// treated as a path. A method passed as a value without being called is not
// followed; none of the handlers below does that.
func (p *srcPkg) callGraph() map[string][]string {
	g := map[string][]string{}
	// The per-file duplicates ("name@file"), by name, built once: looking
	// them up by prefix for every identifier made this graph cost seconds.
	dups := map[string][]string{}
	for k := range p.funcs {
		if i := strings.IndexByte(k, '@'); i >= 0 {
			dups[k[:i]] = append(dups[k[:i]], k)
		}
	}
	for key, fd := range p.funcs {
		if fd.Body == nil {
			continue
		}
		var out []string
		ast.Inspect(fd.Body, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.Ident:
				if _, ok := p.funcs[v.Name]; ok {
					out = append(out, v.Name)
				}
				out = append(out, dups[v.Name]...)
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
					out = append(out, p.methods[sel.Sel.Name]...)
				}
			}
			return true
		})
		g[key] = out
	}
	return g
}

// reach returns every function reachable from roots, with the path to it.
func reach(g map[string][]string, roots []string, stop map[string]bool) map[string]string {
	seen := map[string]string{}
	var queue []string
	for _, r := range roots {
		seen[r] = r
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if stop[n] {
			continue
		}
		for _, m := range g[n] {
			if _, ok := seen[m]; !ok {
				seen[m] = seen[n] + " -> " + m
				queue = append(queue, m)
			}
		}
	}
	return seen
}

// handlerFuncName is the Go function a handlerOps entry dispatches to.
func (p *srcPkg) handlerFuncs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range p.files {
		ast.Inspect(f, func(x ast.Node) bool {
			vs, ok := x.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "handlerOps" {
				return true
			}
			cl := vs.Values[0].(*ast.CompositeLit)
			for _, e := range cl.Elts {
				kv := e.(*ast.KeyValueExpr)
				op := exprText(kv.Key)
				if b, ok := kv.Key.(*ast.BasicLit); ok {
					op, _ = strconv.Unquote(b.Value)
				}
				h := kv.Value.(*ast.CompositeLit)
				out[op] = exprText(h.Elts[len(h.Elts)-1])
			}
			return false
		})
	}
	if len(out) != len(handlerOps) {
		t.Fatalf("read %d handler entries from the source, the table has %d", len(out), len(handlerOps))
	}
	return out
}

// execSites names the functions that start a process directly.
func (p *srcPkg) execSites() map[string]string {
	out := map[string]string{}
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		recv, sel := selName(c)
		if (recv == "exec" && (sel == "Command" || sel == "CommandContext")) ||
			(recv == "os" && sel == "StartProcess") ||
			(recv == "syscall" && (sel == "Exec" || sel == "ForkExec" || sel == "StartProcess")) {
			out[fn] = file
		}
	})
	return out
}

// shellPrograms are the command interpreters a "no shell" claim rules out.
var shellPrograms = map[string]bool{
	"sh": true, "/bin/sh": true, "bash": true, "/bin/bash": true, "zsh": true, "dash": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true,
}

// Fixed argv, and no shell in file handlers. The file ops are Go handlers:
// nothing any of them can reach runs a shell, and the one process any of
// them can start is the local search agent that dcn_grant_sync brings up for
// a store granted "search" — a Python interpreter found on PATH running the
// signed agent. ctx_extract is the one context op that runs a program, a
// named tool from a fixed table (TestCtxExtractRefusesAnUnknownTool), and is
// left out on purpose.
func TestFileHandlersStartNoShell(t *testing.T) {
	p := parseSources(t)
	g := p.callGraph()
	h := p.handlerFuncs(t)
	var roots []string
	for op, fn := range h {
		if (strings.HasPrefix(op, "ctx_") && op != "ctx_extract") || strings.HasPrefix(op, "dcn_") ||
			op == "backup_fetch" || op == "backup_push" || op == "backup_reseal" || op == "backup_list" {
			roots = append(roots, fn)
		}
	}
	sort.Strings(roots)
	if len(roots) < 10 {
		t.Fatalf("found only %d file handlers (%v); the table read went wrong", len(roots), roots)
	}
	// The management lane's framing and audit are shared by every op and
	// write the bastion's own records; they are checked where they live.
	stop := map[string]bool{"sendMgmt": true, "sendMgmtExit": true, "refuseMgmt": true}
	seen := reach(g, roots, stop)
	agent := map[string]bool{"faPython": true, "faSignManifest": true, "faRunOnce": true}
	starters := p.execSites()
	for fn, file := range starters {
		path, ok := seen[fn]
		if !ok {
			continue
		}
		if !agent[fn] {
			t.Errorf("a file handler can reach %s (%s), which starts a process: %s", fn, file, path)
		}
	}
	for fn := range agent {
		if _, ok := starters[fn]; !ok {
			t.Errorf("%s no longer starts a process; take it out of this test", fn)
		}
	}
	// Nothing a file handler can reach names a shell as the program.
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		if _, ok := seen[fn]; !ok {
			return
		}
		recv, sel := selName(c)
		if recv != "exec" || (sel != "Command" && sel != "CommandContext") {
			return
		}
		prog := c.Args[0]
		if sel == "CommandContext" {
			prog = c.Args[1]
		}
		for _, l := range stringLits(prog) {
			if shellPrograms[l] {
				t.Errorf("%s:%s runs %s, reachable from a file handler", file, fn, l)
			}
		}
	})
}

// Fixed argv: the one allowlisted op has one fixed command line, and the
// place that runs it builds the command from the table alone.
func TestTheAllowlistedOpRunsItsTableArgvOnly(t *testing.T) {
	if len(p8AllowedOps) != 1 || strings.Join(p8AllowedOps["uptime"], " ") != "uptime" {
		t.Fatalf("the allowlisted argv table changed: %v — an op that takes arguments must validate them per op, and this test with it", p8AllowedOps)
	}
	p := parseSources(t)
	var n int
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		if file != "mgmt.go" {
			return
		}
		if recv, sel := selName(c); recv == "exec" && (sel == "Command" || sel == "CommandContext") {
			n++
			for _, a := range c.Args[1:] {
				txt := exprText(a)
				if !strings.HasPrefix(txt, "argv") {
					t.Errorf("mgmt.go:%s builds a command from %s; only the table's argv may reach it", fn, txt)
				}
			}
			ast.Inspect(c, func(x ast.Node) bool {
				if s, ok := x.(*ast.SelectorExpr); ok && s.Sel.Name == "Args" {
					t.Errorf("mgmt.go:%s passes %s to a command", fn, exprText(s))
				}
				return true
			})
		}
	})
	if n != 1 {
		t.Fatalf("mgmt.go starts %d commands; the allowlisted op is the one", n)
	}
}

// Observation changes nothing on the machine. What an observe or computer
// op can reach writes nothing through Go and signals nothing, apart from the
// bastion's own records of the op (the audit line and the observe journal,
// machinestore.go), and runs only the programs pinned here, each with the
// arguments that make it a read.
func TestObserveOpsWriteNothing(t *testing.T) {
	p := parseSources(t)
	g := p.callGraph()
	h := p.handlerFuncs(t)
	var roots []string
	for op, fn := range h {
		if strings.HasPrefix(op, "observe:") || strings.HasPrefix(op, "computer:") {
			roots = append(roots, fn)
		}
	}
	if len(roots) != 18 {
		t.Fatalf("expected the 15 observe and 3 computer handlers, found %d", len(roots))
	}
	stop := map[string]bool{"sendMgmt": true, "sendMgmtExit": true, "refuseMgmt": true,
		"storeRecordObserve": true}
	seen := reach(g, roots, stop)

	writes := map[string]bool{
		"os.WriteFile": true, "os.Create": true, "os.Remove": true, "os.RemoveAll": true,
		"os.Rename": true, "os.Mkdir": true, "os.MkdirAll": true, "os.MkdirTemp": true, "os.CreateTemp": true,
		"os.Chmod": true, "os.Chown": true, "os.Lchown": true, "os.Chtimes": true,
		"os.Symlink": true, "os.Link": true, "os.Truncate": true,
		"syscall.Kill": true, "unix.Kill": true, "syscall.Mount": true, "unix.Mount": true,
		"syscall.Unlink": true, "unix.Unlink": true, "syscall.Reboot": true, "unix.Reboot": true,
	}
	// wrapper -> index of the program argument
	runners := map[string]int{"observeExec": 1, "textOf": 1, "runFixed": 0, "runTimed": 0, "runFixedEnv": 1}
	programs := map[string]bool{}
	for fn, path := range seen {
		fd := p.funcs[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(x ast.Node) bool {
			c, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			recv, sel := selName(c)
			if writes[recv+"."+sel] {
				t.Errorf("%s calls %s.%s, reachable from an observe op: %s", fn, recv, sel, path)
			}
			if recv == "os" && sel == "OpenFile" && len(c.Args) > 1 && exprText(c.Args[1]) != "os.O_RDONLY" {
				t.Errorf("%s opens a file for writing, reachable from an observe op: %s", fn, path)
			}
			if sel == "Kill" || sel == "Signal" {
				t.Errorf("%s signals a process (%s.%s), reachable from an observe op: %s", fn, recv, sel, path)
			}
			at, ok := runners[exprText(c.Fun)]
			if !ok || len(c.Args) <= at {
				return true
			}
			if _, self := runners[fn]; self {
				return true // the wrapper passing its own argument on
			}
			var argv []string
			for _, a := range c.Args[at:] {
				l := stringLits(a)
				if len(l) == 1 {
					argv = append(argv, l[0])
				} else {
					argv = append(argv, "<"+exprText(a)+">")
				}
			}
			if len(argv[0]) > 40 {
				argv[0] = argv[0][:40]
			}
			for i := range argv {
				if len(argv[i]) > 40 {
					argv[i] = argv[i][:40] + "…"
				}
			}
			programs[strings.Join(argv, " ")] = true
			return true
		})
	}
	var got []string
	for k := range programs {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{
		"apt-get -s upgrade", // -s: simulate, changes nothing
		"df -P",
		"dmesg -T",
		"iptables -S",
		"journalctl -n1 -o short-unix --no-pager",
		// observe:logins: sshd's lines over a window of whole hours.
		"journalctl <sinceArg> -o short-iso --no-pager -q --lines=50000 _COMM=sshd _COMM=sshd-session _COMM=sshd-auth _UID=0 + _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service _UID=0",
		// observe:journal: one unit this machine's own lists name, over minutes.
		"journalctl <unitArg> <sinceArg> -o short-iso --no-pager -q --lines=5000",
		"kubectl --kubeconfig <observeKubeconfig> get nodes -o json",
		"kubectl --kubeconfig <observeKubeconfig> get pods -A -o json",
		"nft list chain inet pubwall input",
		"nft list ruleset",
		"nft list table inet pubwall",
		"osascript -e <windowsScript>",                  // lists windows (TestNoInputInjection reads the script)
		"osascript -l JavaScript -e <darwinTreeScript>", // reads one app's accessibility tree
		"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <windowsTreeEncoded>",
		"python3 -c <linuxTreeScript>",
		"ss -tlnpH",
		"ss -ulnpH",
		"system_profiler SPApplicationsDataType -json",
		"systemctl is-active fail2ban",
		"systemctl list-timers --all --no-legend --plain",
		"systemctl list-unit-files --no-legend --plain", // observe:journal's unit check
		"systemctl list-units --all --no-legend --plain",
		"systemctl list-units --failed --no-legend --plain",
		"ufw status",
		"ufw status verbose",
		"wmctrl -lp",
		"xprop -root _NET_ACTIVE_WINDOW",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the programs an observe or computer op runs changed. Every one must be a read; "+
			"review the change and update this table.\n got: %q\nwant: %q", got, want)
	}
}

// No input injection lives in the bastion. No program that types, clicks
// or moves a pointer is run, no Windows input API is loaded, and none of the
// scripts handed to an interpreter asks for a keystroke, a click or an
// accessibility action — on any platform.
func TestNoInputInjection(t *testing.T) {
	p := parseSources(t)
	injectors := map[string]bool{"xdotool": true, "ydotool": true, "wtype": true, "xte": true,
		"cliclick": true, "nircmd": true, "AutoHotkey": true, "autohotkey": true}
	runners := map[string]int{"observeExec": 1, "textOf": 1, "runFixed": 0, "runTimed": 0, "runFixedEnv": 1}
	inputAPIs := map[string]bool{"SendInput": true, "keybd_event": true, "mouse_event": true,
		"SetCursorPos": true, "BlockInput": true, "SendKeys": true}
	p.eachCall(func(file, fn string, c *ast.CallExpr) {
		recv, sel := selName(c)
		at := -1
		switch {
		case recv == "exec" && sel == "Command":
			at = 0
		case recv == "exec" && sel == "CommandContext":
			at = 1
		default:
			if i, ok := runners[exprText(c.Fun)]; ok {
				at = i
			}
		}
		if at >= 0 && len(c.Args) > at {
			for _, l := range stringLits(c.Args[at]) {
				if injectors[filepath.Base(l)] {
					t.Errorf("%s:%s runs %s, an input-injection tool", file, fn, l)
				}
			}
		}
		if sel == "NewProc" || sel == "FindProc" || sel == "MustFindProc" {
			for _, l := range stringLits(c) {
				if inputAPIs[l] {
					t.Errorf("%s:%s loads %s, an input-injection API", file, fn, l)
				}
			}
		}
	})
	verbs := []string{"keystroke", "key code", "click at", "click button", "click menu",
		".Invoke()", "InvokePattern", ".SetValue(", "SendKeys", "do_action", "doAction",
		"generate_keyboard_event", "generate_mouse_event", "pyautogui", "pynput", "XTest",
		"CGEventPost", "/dev/uinput"}
	// The scripts live in the computer_* files; agents.go names injection
	// tools too, as things to DETECT on the machine, which is not running them.
	for name, f := range p.files {
		if !strings.HasPrefix(name, "computer") && !strings.HasPrefix(name, "observe") {
			continue
		}
		for _, s := range stringLits(f) {
			for _, v := range verbs {
				if strings.Contains(s, v) {
					t.Errorf("%s carries %q in a string: an input-injection call", name, v)
				}
			}
		}
	}
	for name, f := range p.files {
		ast.Inspect(f, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok && (inputAPIs[id.Name] || id.Name == "CGEventPost") {
				t.Errorf("%s refers to %s, an input-injection API", name, id.Name)
			}
			return true
		})
	}
}

// Scoped tunnel, on the path a rotation takes. Rotation and failover reach the
// live device through package variables, so their tests can drive a probe
// without a WireGuard peer (rotate.go). The scope claim is tested on swapPeer
// itself (claims_tunnel_test.go), so it holds for the running code only while
// those variables are swapPeer and its siblings: declared with them, and
// assigned or addressed nowhere outside tests.
func TestARotationReachesTheDeviceOnlyThroughSwapPeer(t *testing.T) {
	p := parseSources(t)
	declared := map[string]string{
		"livePeerSwap":      "swapPeer",
		"liveHandshake":     "handshakeWithin",
		"liveLastHandshake": "return lastHandshake(…)",
		"dialForRouteCheck": "net.DialTimeout",
	}
	initText := func(e ast.Expr) string {
		// liveLastHandshake adapts lastHandshake's interface parameter to the
		// device type; anything more in that literal is a different function.
		if fl, ok := e.(*ast.FuncLit); ok && len(fl.Body.List) == 1 {
			if r, ok := fl.Body.List[0].(*ast.ReturnStmt); ok && len(r.Results) == 1 {
				if c, ok := r.Results[0].(*ast.CallExpr); ok && exprText(c.Fun) == "lastHandshake" {
					return "return lastHandshake(…)"
				}
			}
		}
		return exprText(e)
	}
	seen := map[string]int{}
	for name, f := range p.files {
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.VAR {
				continue
			}
			for _, s := range g.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					want, ok := declared[n.Name]
					if !ok {
						continue
					}
					seen[n.Name]++
					if i >= len(vs.Values) || initText(vs.Values[i]) != want {
						t.Errorf("%s declares %s, which must start as %s", name, n.Name, want)
					}
				}
			}
		}
		ast.Inspect(f, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.AssignStmt:
				for _, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok && declared[id.Name] != "" {
						t.Errorf("%s:%d assigns %s; only a test may replace it",
							name, p.fset.Position(v.Pos()).Line, id.Name)
					}
				}
			case *ast.UnaryExpr:
				if id, ok := v.X.(*ast.Ident); ok && v.Op == token.AND && declared[id.Name] != "" {
					t.Errorf("%s:%d takes the address of %s, which would let it be replaced",
						name, p.fset.Position(v.Pos()).Line, id.Name)
				}
			}
			return true
		})
	}
	for n := range declared {
		if seen[n] != 1 {
			t.Errorf("%s is declared %d times; the table expects it once", n, seen[n])
		}
	}
	// And what the running code holds when this test runs: no earlier test left
	// a stub behind.
	same := func(a, b any) bool { return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer() }
	if !same(livePeerSwap, swapPeer) || !same(liveHandshake, handshakeWithin) || !same(dialForRouteCheck, net.DialTimeout) {
		t.Error("a rotation seam does not hold the live function; a test replaced it and did not put it back")
	}
}
