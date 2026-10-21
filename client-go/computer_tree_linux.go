//go:build linux

package main

import (
	"errors"
	"os/exec"
	"strings"
)

// Linux: AT-SPI 2 through python3 + gi (Atspi), a fixed script. The
// accessibility bus is per session and found through the X display, so the
// display discovered for computer:windows is handed to the helper. A box
// without the binding says so, with the package to install.

const computerTreeKind = "atspi-python"

const linuxTreeScript = `
import json, os, sys
try:
    import gi
    gi.require_version("Atspi", "2.0")
    from gi.repository import Atspi
except Exception as e:
    print(json.dumps({"error": "AT-SPI binding not available: %s (install python3-gi and gir1.2-atspi-2.0)" % e})); sys.exit(0)
pid = int(os.environ["PRIVATAE_TARGET_PID"]); cap = int(os.environ["PRIVATAE_MAX_NODES"])
count = 0; trunc = False
def node(el, depth):
    global count, trunc
    if count >= cap or depth > 40:
        trunc = True; return None
    count += 1
    n = {"role": Atspi.role_get_name(el.get_role()).replace(" ", "_")}
    name = el.get_name() or ""
    if name: n["name"] = name
    try:
        st = el.get_state_set()
        n["enabled"] = bool(st.contains(Atspi.StateType.ENABLED))
        if st.contains(Atspi.StateType.FOCUSED): n["focused"] = True
        if not st.contains(Atspi.StateType.SHOWING): n["offscreen"] = True
    except Exception: pass
    try:
        r = el.get_extents(Atspi.CoordType.SCREEN)
        if r.width or r.height: n.update(x=r.x, y=r.y, w=r.width, h=r.height)
    except Exception: pass
    try:
        # Accessible carries a deprecated zero-arg get_text() that shadows
        # Text.get_text(start, end) on the gi class, so call the interface
        # method explicitly.
        t = el.get_text_iface()
        if t is not None:
            v = Atspi.Text.get_text(t, 0, min(Atspi.Text.get_character_count(t), 200))
            if v: n["value"] = v
    except Exception: pass
    kids = []
    try:
        for i in range(el.get_child_count()):
            k = node(el.get_child_at_index(i), depth + 1)
            if k: kids.append(k)
            if trunc: break
    except Exception: pass
    if kids: n["children"] = kids
    return n
def fail(msg):
    print(json.dumps({"error": msg})); sys.exit(0)
try:
    desk = Atspi.get_desktop(0)
    n_apps = desk.get_child_count()
except Exception as e:
    fail("could not reach the accessibility bus: %s" % e)
app = None
for i in range(n_apps):
    try:
        a = desk.get_child_at_index(i)
        if a is not None and a.get_process_id() == pid: app = a; break
    except Exception: continue
if app is None:
    fail("pid %d has no AT-SPI application (not running, no toolkit support, or accessibility off)" % pid)
wins = []
try:
    for i in range(app.get_child_count()):
        w = node(app.get_child_at_index(i), 0)
        if w: wins.append(w)
    name = app.get_name() or ""
except Exception as e:
    fail("the application stopped answering the accessibility bus: %s" % e)
print(json.dumps({"app": name, "truncated": trunc, "windows": wins}))
`

func readTree(pid, maxNodes int) ([]byte, error) {
	if !execOnPath("python3") {
		return nil, errors.New("python3 not installed — the AT-SPI reader needs python3 with gi (python3-gi, gir1.2-atspi-2.0)")
	}
	env := helperEnv(pid, maxNodes)
	if d := x11Display(); d != "" {
		env = append(env, "DISPLAY="+d)
	}
	out, err := runFixedEnv(env, "python3", "-c", linuxTreeScript)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, errors.New("AT-SPI walk failed: " + truncate(strings.TrimSpace(string(ee.Stderr)), 300))
		}
		return nil, errors.New("python3 failed: " + err.Error())
	}
	return out, nil
}
