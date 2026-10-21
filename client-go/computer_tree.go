package main

// computer:tree — the ACCESSIBILITY TREE of one application's windows: the
// middle rung of the machine map. Where an app offers no
// scripting door, this is how the host sees it: the app's OWN names for its
// controls, their roles, whether they are enabled and where they are — text,
// not pixels, and exact. It is a READ. Nothing here presses a button.
//
// Each OS has one accessibility API and one fixed helper that walks it:
//   Windows  UI Automation, through PowerShell's UIAutomationClient assembly
//            (ships with .NET Framework on every Windows).
//   macOS    the AX tree through System Events, in JXA (osascript -l
//            JavaScript). Needs the Accessibility permission, like
//            computer:windows.
//   Linux    AT-SPI 2, through python3 + gi (Atspi). Absent → says so.
//
// "Leech, don't adopt": no COM, AX or D-Bus binding lands in the bastion; the
// helper scripts are fixed strings, the target pid and the node cap travel in
// the environment (never in argv, never interpolated), and the helper answers
// JSON that this side re-validates and re-counts.
//
// Args (from the pod, validated here): [pid, max_nodes?]. pid must be a
// positive integer that computer:windows or the agent scan reported — the
// host names a window by its owner, never by guessing.

import (
	"encoding/json"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// The caps match the pod side (the host's machine map): a tree is answered to
// the host through a 100 KB reply wall, and a real node is ~120 bytes, so
// 500 nodes is what arrives whole. Fewer nodes also keeps the macOS walk (up
// to nine Apple Events per node) inside the op's timeout.
const (
	treeDefaultMaxNodes = 500
	treeMaxNodes        = 800
	treeMaxDepth        = 40
	treeMaxText         = 120 // name / id / value are cut to this many characters
)

// computerNode is one element of the tree. Keys are what a recorded step
// addresses a control by: role + name (what a person sees), then the app's
// own id when it has one. Bounds are screen pixels.
type computerNode struct {
	Role      string          `json:"role"`
	Name      string          `json:"name,omitempty"`
	ID        string          `json:"id,omitempty"`
	Value     string          `json:"value,omitempty"`
	X         int             `json:"x,omitempty"`
	Y         int             `json:"y,omitempty"`
	W         int             `json:"w,omitempty"`
	H         int             `json:"h,omitempty"`
	Enabled   *bool           `json:"enabled,omitempty"`
	Focused   bool            `json:"focused,omitempty"`
	Offscreen bool            `json:"offscreen,omitempty"`
	Children  []*computerNode `json:"children,omitempty"`
}

// treeReport is the wire shape. Windows are the app's top-level windows,
// each a tree. node_count / truncated are recounted here, not trusted.
type treeReport struct {
	Platform  string          `json:"platform"`
	Scan      string          `json:"scan"`
	Supported bool            `json:"supported"`
	Reason    string          `json:"reason,omitempty"`
	ScannedAt string          `json:"scanned_at"`
	PID       int             `json:"pid,omitempty"`
	App       string          `json:"app,omitempty"`
	NodeCount int             `json:"node_count"`
	Truncated bool            `json:"truncated,omitempty"`
	Windows   []*computerNode `json:"windows,omitempty"`
}

// helperTree is what every helper answers: {app, truncated, windows:[node…]}.
type helperTree struct {
	App       string          `json:"app"`
	Truncated bool            `json:"truncated"`
	Error     string          `json:"error"`
	Windows   []*computerNode `json:"windows"`
}

func parseTreeArgs(args []string) (pid, maxNodes int, err error) {
	if len(args) < 1 {
		return 0, 0, errors.New("computer:tree needs the owning pid (from computer:windows)")
	}
	pid, err = strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil || pid <= 1 {
		return 0, 0, errors.New("computer:tree: pid must be a positive integer")
	}
	maxNodes = treeDefaultMaxNodes
	if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(args[1]))
		if err != nil || n <= 0 {
			return 0, 0, errors.New("computer:tree: max_nodes must be a positive integer")
		}
		if n > treeMaxNodes {
			n = treeMaxNodes
		}
		maxNodes = n
	}
	return pid, maxNodes, nil
}

// boundTree recounts the helper's answer and enforces the node cap and depth
// cap on THIS side too — the helper is trusted for nothing but the walk.
func boundTree(wins []*computerNode, maxNodes int) (out []*computerNode, count int, truncated bool) {
	var walk func(n *computerNode, depth int) *computerNode
	walk = func(n *computerNode, depth int) *computerNode {
		if n == nil || count >= maxNodes || depth > treeMaxDepth {
			truncated = true
			return nil
		}
		count++
		c := *n
		c.Children = nil
		c.Name, c.ID, c.Value = cutRunes(c.Name, treeMaxText), cutRunes(c.ID, treeMaxText), cutRunes(c.Value, treeMaxText)
		for _, ch := range n.Children {
			if k := walk(ch, depth+1); k != nil {
				c.Children = append(c.Children, k)
			}
		}
		return &c
	}
	for _, w := range wins {
		if k := walk(w, 0); k != nil {
			out = append(out, k)
		}
	}
	return out, count, truncated
}

func computerTreeReport(args []string) treeReport {
	rep := treeReport{Platform: runtime.GOOS, Scan: computerTreeKind,
		ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	pid, maxNodes, err := parseTreeArgs(args)
	if err != nil {
		rep.Reason = err.Error()
		return rep
	}
	rep.PID = pid
	if !computerObserveSupported {
		rep.Reason = "no accessibility-tree reader for this platform"
		return rep
	}
	raw, err := readTree(pid, maxNodes)
	if err != nil {
		rep.Reason = err.Error()
		if strings.Contains(rep.Reason, "signal: killed") {
			// The helper hit the op's timeout: a busy app on macOS can cost
			// several Apple Events per node. Say what to do, not "killed".
			rep.Reason = "reading this app's tree took longer than the op allows — ask again with a smaller max_nodes"
		}
		return rep
	}
	var ht helperTree
	if err := json.Unmarshal(raw, &ht); err != nil {
		rep.Reason = "tree helper answered, not with a tree: " + truncate(err.Error(), 200)
		return rep
	}
	if ht.Error != "" {
		rep.Reason = ht.Error
		return rep
	}
	rep.Supported = true
	rep.App = ht.App
	rep.Windows, rep.NodeCount, rep.Truncated = boundTree(ht.Windows, maxNodes)
	rep.Truncated = rep.Truncated || ht.Truncated
	if rep.Windows == nil {
		rep.Windows = []*computerNode{}
	}
	return rep
}

func handleComputerTree(ws *websocket.Conn, _ string, args []string) {
	rep := computerTreeReport(args)
	b, err := json.Marshal(rep)
	if err != nil {
		sendMgmt(ws, 'R', []byte("report: "+err.Error()+"\n"))
		sendMgmtExit(ws, 1)
		return
	}
	// A bad ARGUMENT is the caller's fault and reads as such (exit 2, the
	// usage-error convention); a blind box is still a true answer (exit 0).
	if !rep.Supported && rep.PID == 0 {
		sendMgmt(ws, 'R', []byte(rep.Reason+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	sendMgmt(ws, 'O', append(b, '\n'))
	sendMgmtExit(ws, 0)
}

// cutRunes shortens a label to n characters on a character boundary — control
// names are the user's language, and a byte cut would split a multibyte one.
func cutRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// helperEnv is the only channel a caller value takes into a helper.
func helperEnv(pid, maxNodes int) []string {
	return []string{"PRIVATAE_TARGET_PID=" + strconv.Itoa(pid), "PRIVATAE_MAX_NODES=" + strconv.Itoa(maxNodes)}
}
