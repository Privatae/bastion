package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A name swapped for a special file between the walk's look and its open must
// never be opened: opening a device runs its driver (a watchdog arms, a tape
// rewinds on close, a serial line raises DTR), whatever is read after. A named
// pipe stands in for any of them, since anyone can make one, and inotify
// reports every open of it except one made only as a path (O_PATH), which runs
// no driver code. Both a name looked at as a plain file and one looked at as
// a folder are swapped.
func TestMakeTarNeverOpensASpecialFileSwappedInBeforeTheOpen(t *testing.T) {
	for _, swap := range []string{"a.txt", "sub"} {
		t.Run(swap, func(t *testing.T) {
			_, _, tree := outsideAndTree(t)
			in, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
			if err != nil {
				t.Skipf("no inotify: %v", err)
			}
			defer unix.Close(in)
			watched := false
			packTreeBeforeOpen = func(rel string) {
				if rel != swap {
					return
				}
				p := filepath.Join(tree, swap)
				if err := os.RemoveAll(p); err != nil {
					t.Errorf("remove %s: %v", p, err)
					return
				}
				if err := unix.Mkfifo(p, 0o644); err != nil {
					t.Errorf("mkfifo %s: %v", p, err)
					return
				}
				if _, err := unix.InotifyAddWatch(in, p, unix.IN_OPEN); err != nil {
					t.Errorf("watch %s: %v", p, err)
					return
				}
				watched = true
			}
			defer func() { packTreeBeforeOpen = nil }()
			b, skipped, err := packWorktree(tree)
			if err != nil {
				t.Fatalf("packWorktree: %v", err)
			}
			if !watched {
				t.Fatal("the swap never ran")
			}
			buf := make([]byte, 4096)
			if n, err := unix.Read(in, buf); n > 0 {
				t.Fatalf("the special file swapped in for %s was opened (%d bytes of inotify events)", swap, n)
			} else if err != unix.EAGAIN {
				t.Fatalf("read inotify: %d %v", n, err)
			}
			if _, ok := tarEntries(t, b)[swap]; ok {
				t.Fatalf("%s was a named pipe when it was opened and must be left out", swap)
			}
			if !strings.Contains(","+strings.Join(skipped, ",")+",", ","+swap+",") {
				t.Fatalf("%s must be named as left out, got %v", swap, skipped)
			}
		})
	}
}
