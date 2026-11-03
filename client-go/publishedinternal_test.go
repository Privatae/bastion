package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The member repository publishes this tree to strangers byte for byte, and
// its release step refuses outright a tree that carries any of the classes
// below. Each is checked here as well, so a change that brings one in fails
// before it merges, not after a release has been built and signed from it.
//
// A class is described, never named: a comment says what happened and why, not
// on which of our machines, by whom, under which ticket, or on which day it was
// decided. Test data is invented (example.com, .example, the 9000 range).
//
// Not checked here: names held outside this repository (they cannot be listed
// in a published file; the release step and the personal-data check read them
// from the machine they are kept on), and the two classes the release step
// compares against the previous release instead of refusing outright: paths
// under root's home directory, which the bastion's own state and its tests of
// credential-store refusals legitimately use, and the bastion's own tunnel
// addresses in the private range.
//
// Every pattern is written so that this file does not match it: a bracketed
// letter keeps the text from being the word it finds.
var publishedInternalClasses = []struct {
	name string
	re   *regexp.Regexp
}{
	{"a machine of the platform's own fleet",
		regexp.MustCompile(`mgmt-[12]|platform-meta[l]|entity-poo[l]|edge-vi[n]|edge-hi[l]|dmz-[a-z]+-[0-9]`)},
	{"a credential store of the platform",
		regexp.MustCompile(`gitea-[s]kema-credentials|/roo[t]/\.config/git|INTERNAL_API_SECRE[T]`)},
	{"a ticket id", regexp.MustCompile(`T-[0-9]{4}\b|R-[0-9]{3}\b`)},
	{"the name of a person or a review agent who worked on the code",
		regexp.MustCompile(`\b(Fabl[e]|Maddi[e]|Opu[s])\b|[Cc]ase[y]`)},
	{"a dated decision", regexp.MustCompile(`(Decided|Reported|Measured|measured) 20[0-9]{2}-[0-9]{2}`)},
	{"a design document reference", regexp.MustCompile(`DESIGN-[a-z]|plan [§]`)},
	{"the old module path", regexp.MustCompile(`github\.com/privata[e]`)},
	{"the platform's install directory", regexp.MustCompile(`/opt/privata[e]`)},
	{"an address in the platform's fleet mesh", regexp.MustCompile(`fd0[0]:aa:`)},
}

// publishedInternalHits returns "class: line N" for every line of src that a
// class matches.
func publishedInternalHits(src string) []string {
	var hits []string
	for i, line := range strings.Split(src, "\n") {
		for _, c := range publishedInternalClasses {
			if c.re.MatchString(line) {
				hits = append(hits, strconv.Itoa(i+1)+": "+c.name)
			}
		}
	}
	return hits
}

func TestPublishedSourceNamesNothingInternal(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	files := publishedFiles(t, root)
	if len(files) < 50 {
		t.Fatalf("found only %d files under %s; the scan is not looking at the repository", len(files), root)
	}
	var hits []string
	for _, rel := range files {
		for _, h := range publishedInternalHits(rel) {
			hits = append(hits, rel+" (in the file name) "+h[strings.Index(h, " ")+1:])
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a tracked file deleted in the working tree
		}
		for _, h := range publishedInternalHits(string(data)) {
			hits = append(hits, rel+":"+h)
		}
	}
	// The lines themselves are not printed: a hit of the first two classes can
	// be the very value that must not be published, and a CI log is published too.
	if len(hits) > 0 {
		t.Errorf("%d published lines name something internal; describe it instead, with invented values:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}

// The check itself: each class fires on a planted line and stays quiet on its
// look-alikes. Planted lines carry a "|" that is removed before they are read.
func TestPublishedInternalCheckCatchesEachClass(t *testing.T) {
	live := func(s string) string { return strings.ReplaceAll(s, "|", "") }
	for _, line := range []string{
		"seen on mgmt|-2 at noon", "ssh platform-met|al", "the entity-po|ol nodes", "via edge-v|in",
		"edge-h|il took over", "dmz-ro|uter-1 is up",
		"read /ro|ot/.config/g|it/creds", "gitea-sk|ema-credentials", "INTERNAL_API_SEC|RET=x",
		"fixed in T-|1234", "see R-|101.",
		"Fab|le found it", "per Mad|die", "Op|us said so", "Ca|sey asked", `owner "ca|sey"`,
		"Decid|ed 2026-10-01: keep it", "measu|red 2026-11-03 on a box",
		"DESIGN|-bastion.md", "plan| § 4",
		"github.com/priv|atae/bastion", "/opt/priv|atae/bin", "addr fd0|0:aa::1",
	} {
		if len(publishedInternalHits(live(line))) == 0 {
			t.Errorf("%q: not caught", live(line))
		}
	}
	for _, line := range []string{
		"mgmt-3 is not ours", "platform metal", "edge-v",
		"dmz-router", "~/.config/git", "T-123 and T-12345x", "R-1000",
		"Fables and Opuses", "Maddies", "a case, yes", "decided in 2026",
		"design doc", "github.com/example/thing", "/opt/example/privatae-bastion",
		"fd12:3456::a:1", "fdaa::1",
	} {
		if hits := publishedInternalHits(live(line)); len(hits) != 0 {
			t.Errorf("%q: false hit %v", line, hits)
		}
	}
}
