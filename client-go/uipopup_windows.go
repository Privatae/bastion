//go:build windows

package main

// uipopup_windows.go — the approvals page as a small window of its own.
//
// A browser TAB is the wrong shape for "something needs your yes": it lands in
// whatever window was last used, behind whatever the person was doing, among
// forty other tabs. Edge's app mode (`--app=<url>`) opens the page in a
// window with no tabs, no address bar and a size we choose — a popup, which is
// what the person asked for — and Edge ships with every supported Windows.
//
// NOT a native dialog, and that is forced rather than chosen: the release is
// built at CGO_ENABLED=0 (tray_windows.go), and a native window with a list and
// buttons in pure Go is a GUI toolkit this binary does not carry. The page is
// the same server-rendered page the front page uses, so there is one set of
// words and one approve path, not two.
//
// FALLBACK. No Edge where we look, or Edge will not start: the default browser,
// exactly as openLocalUI does. The person still gets the page; it is a tab.

import (
	"os"
	"os/exec"
	"path/filepath"
)

// popupWindowSize is wide enough for an approval card's two buttons side by side
// and tall enough for three cards before scrolling.
const popupWindowSize = "560,760"

func openPopupWindow(url string) error {
	if edge := findEdge(); edge != "" {
		// NOT hideConsole: Edge is a GUI program with no console, and the flag
		// that hides one asks Windows to start the first window hidden — which
		// a cold-started Edge may honour, opening the popup invisible.
		cmd := exec.Command(edge, "--app="+url, "--window-size="+popupWindowSize)
		err := cmd.Start()
		if err == nil {
			go func() { _ = cmd.Wait() }()
			return nil
		}
		uilogf("approvals popup: could not start Edge (%v); opening the default browser\n", err)
	}
	return openBrowser(url)
}

// approvalsOpener is what a click on an approval notification opens: the
// daemon's own popup, or, in the tray beside a system service, the tray's page
// (tray_pipe_windows.go sets it before the notifier starts).
var approvalsOpener = openApprovalsPopup

// openApprovalsPopup is what the tray's approvals line and a click on the
// approval notification do: open /approvals, signed in, as a small window.
//
// It goes through localUIEntryURLTo exactly as openLocalUI goes through
// localUIEntryURL — a one-use ticket minted against the running daemon — so it
// cannot hand out a link that does not authenticate, and the ticket's redirect
// lands on the page itself rather than on a menu.
func openApprovalsPopup(from string) {
	entry, _, err := localUIEntryURLTo(uiApprovalsPath)
	if err != nil {
		uilogf("%s: %v\n", from, err)
		return
	}
	if err := openPopupWindow(entry); err != nil {
		uilogf("%s: %v\n", from, err)
	}
}

// findEdge looks where Edge installs: machine-wide under both Program Files
// roots, and per-user under LOCALAPPDATA. "" when it is in none of them.
func findEdge() string {
	for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA")} {
		if root == "" {
			continue
		}
		p := filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
