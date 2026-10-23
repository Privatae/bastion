package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A "#NNN" in this repository names a pull request or an issue of the
// development repository, which a reader of the published source cannot open.
// On a forge that links such numbers it points at an unrelated item of the
// published repository instead. A comment or a changelog entry says why
// something is so in the sentence itself.
// Six or more digits is a colour (#000000), not a number anyone cites.
var prNumberRe = regexp.MustCompile(`(^|[^&A-Za-z0-9_])#[0-9]{2,5}\b`)

func TestPublishedSourceCitesNoPullRequestNumber(t *testing.T) {
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
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a tracked file deleted in the working tree
		}
		for i, line := range strings.Split(string(data), "\n") {
			if prNumberRe.MatchString(line) {
				hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
	}
	if len(hits) > 0 {
		t.Errorf("%d published lines cite a pull request or issue by number; state the reason instead:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}

func TestPullRequestNumberCheck(t *testing.T) {
	for line, want := range map[string]bool{
		"// refused here (review of #" + "100).": true,
		"see #" + "1234 for the rest":            true,
		"#" + "42 at the start":                  true,
		"## 0.55.0":                              false,
		"&#" + "123; an HTML entity":             false,
		"color: #fff":                            false,
		`stop-color="#000000"`:                   false,
		"step #1 of 3":                           false,
		"x#" + "12 glued to a name":              false,
	} {
		if got := prNumberRe.MatchString(line); got != want {
			t.Errorf("%q: matched %v, want %v", line, got, want)
		}
	}
}
