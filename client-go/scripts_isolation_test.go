package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every script in scripts/ that starts a bastion in namespaces of its own
// hides ALL of /run and /tmp, never a chosen subdirectory of them, and refuses
// to go on while it can still see the machine's own bastion. A run that put a
// tmpfs over /run/privatae but not /run/privatae-bastion replaced a live
// bastion's ask.sock and context.sock on the machine running the tests.
//
// MUTATION: the e2e script's /run mount back to /run/privatae alone. RESULT: red.
// MUTATION: drop its guard for /run/privatae-bastion. RESULT: red.
// MUTATION: move the guard after the first start of the bastion. RESULT: red.
// MUTATION: drop the PID 1 check before the first mount. RESULT: red.
func TestNamespaceScriptsHideAllOfRunAndTmpAndRefuseToSeeTheLiveBastion(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "scripts", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		if !strings.Contains(s, "unshare") {
			continue
		}
		n++
		name := filepath.Base(p)
		lines := strings.Split(s, "\n")
		at := func(re string) int {
			r := regexp.MustCompile(re)
			for i, l := range lines {
				if strings.HasPrefix(strings.TrimSpace(l), "#") {
					continue
				}
				if r.MatchString(l) {
					return i
				}
			}
			return -1
		}
		runAt := at(`mount -t tmpfs tmpfs /run\s*$`)
		tmpAt := at(`mount -t tmpfs tmpfs /tmp\s*$`)
		if runAt < 0 || tmpAt < 0 {
			t.Errorf("%s: no tmpfs over all of /run (%d) and /tmp (%d)", name, runAt, tmpAt)
		}
		if i := at(`mount -t tmpfs tmpfs /(run|tmp)/`); i >= 0 && (runAt < 0 || i < runAt) {
			t.Errorf("%s:%d hides a subdirectory of /run or /tmp instead of all of it: %s", name, i+1, lines[i])
		}
		guard := at(`/run/privatae-bastion`)
		if guard < 0 || guard < runAt || guard < tmpAt {
			t.Errorf("%s: no guard, after hiding /run and /tmp, that refuses to run while /run/privatae-bastion is visible", name)
		}
		if i := at(`"\$B"|privatae-bastion" (run|pair)|\$BAST`); i >= 0 && guard > i {
			t.Errorf("%s:%d starts a bastion before the guard", name, i+1)
		}
		if at(`unshare .*--pid`) < 0 || at(`unshare .*--mount`) < 0 || at(`unshare .*--net`) < 0 {
			t.Errorf("%s: a bastion runs in private PID, mount and network namespaces", name)
		}
		// The re-exec into the namespaces is chosen by an environment variable
		// (E2E_INNER): one set by the caller skips the unshare, and every mount
		// below then lands on this machine's own /run. So before any mount the
		// script proves it is PID 1 of a namespace of its own.
		pid1 := at(`\[ "?\$\$"? (=|-eq) "?1"? \]`)
		if m := at(`^\s*(mount|mkdir -p [^;&]*&& mount) `); pid1 < 0 || (m >= 0 && pid1 > m) {
			t.Errorf("%s: no check, before its first mount (line %d), that it runs as PID 1 of its own namespace (line %d)", name, m+1, pid1+1)
		}
	}
	if n == 0 {
		t.Fatal("no namespace script found: the glob is wrong")
	}
}
