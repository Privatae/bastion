package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every file in this repository is published as the member repository's
// source, so the platform's former internal name must not appear in any of
// them. The only exceptions are identifiers that installed bastions, the
// harness images, or the host still read or write under that name. Each is
// listed in keptOldNames with what holds it in place; removing one means
// changing the other side first. Prose, comments and the changelog are never
// exceptions.
//
// The forbidden word is assembled from bytes so that this file does not
// contain it outside the exception list.
var oldName = string([]byte{0x73, 0x6b, 0x65, 0x6d, 0x61})

var keptOldNames = []string{
	// Delegation tag the host mints for an agent's environment; agents
	// already launched with it carry this name (env.go agentTokenEnvNames).
	"SKEMA_AGENT_TOKEN",
	// Variables the published harness image reads; it reads no other
	// spelling yet (harness.go, lab.go).
	"SKEMA_SIDECAR_BIND",
	"SKEMA_APP_ID",
	"SKEMA_WORKSPACE",
	// The harness image's workspace root, a path inside that image (lab.go).
	"/var/lib/skema/projects",
	// The device-fingerprint URI SAN in the operator CSR. The host and the
	// platform accept only this prefix at redeem (pair.go fpSANPrefix).
	"urn:skema:hwfp:",
}

// keptOldNameRe matches any kept identifier as a whole token: not preceded or
// followed by a character that would make it part of a longer name.
var keptOldNameRe = func() *regexp.Regexp {
	alts := make([]string, len(keptOldNames))
	for i, k := range keptOldNames {
		alts[i] = regexp.QuoteMeta(k)
	}
	return regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_])(` + strings.Join(alts, "|") + `)`)
}()

// lineHasOldName reports whether line still carries the old name once every
// kept identifier is set aside. A kept identifier glued to a longer name (a
// trailing letter, digit or underscore) is not set aside, so the check still
// sees the old name in it.
func lineHasOldName(line string) bool {
	locs := keptOldNameRe.FindAllStringSubmatchIndex(line, -1)
	var b strings.Builder
	prev := 0
	for _, l := range locs {
		start, end := l[4], l[5] // the identifier itself
		if end < len(line) && isNameByte(line[end]) {
			continue // part of a longer name: not a kept identifier
		}
		b.WriteString(line[prev:start])
		b.WriteByte(' ')
		prev = end
	}
	b.WriteString(line[prev:])
	return strings.Contains(strings.ToLower(b.String()), oldName)
}

func isNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// publishedFiles lists the files the member repository receives: what git
// tracks at the repository root (the publisher stages `git archive` of the
// release commit). Outside a git checkout it walks the tree instead.
func publishedFiles(t *testing.T, root string) []string {
	t.Helper()
	if out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output(); err == nil && len(out) > 0 {
		var files []string
		for _, f := range bytes.Split(out, []byte{0}) {
			if len(f) > 0 {
				files = append(files, string(f))
			}
		}
		return files
	}
	var files []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.Mode().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return files
}

func TestPublishedSourceCarriesNoOldInternalName(t *testing.T) {
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
		if strings.Contains(strings.ToLower(rel), oldName) {
			hits = append(hits, rel+": (in the file name)")
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a tracked file deleted in the working tree
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
		n := 0
		for sc.Scan() {
			n++
			if lineHasOldName(sc.Text()) {
				hits = append(hits, rel+":"+strconv.Itoa(n)+": "+strings.TrimSpace(sc.Text()))
			}
		}
	}
	if len(hits) > 0 {
		t.Errorf("the old internal name appears in %d published lines. Reword prose; an identifier "+
			"may be added to keptOldNames only when something outside this repository still reads it:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}

// The check itself: it must catch the word in prose and in a longer name, and
// pass the kept identifiers.
func TestOldNameCheckCatchesProseAndPassesKeptIdentifiers(t *testing.T) {
	up := strings.ToUpper(oldName)
	title := strings.ToUpper(oldName[:1]) + oldName[1:]
	for _, line := range []string{
		"// see " + oldName + " #649",
		"// the " + title + " server",
		up + "_NEW_VAR",
		keptOldNames[0] + "X", // a kept name with a suffix is a different name
		keptOldNames[len(keptOldNames)-1] + "x " + oldName,
	} {
		if !lineHasOldName(line) {
			t.Errorf("not caught: %q", line)
		}
	}
	for _, line := range []string{
		`var agentTokenEnvNames = []string{"PRIVATAE_AGENT_TOKEN", "SKEMA_AGENT_TOKEN"}`,
		`const fpSANPrefix = "urn:skema:hwfp:"`,
		`labWorkspace = "/var/lib/skema/projects"`,
		`- {name: SKEMA_WORKSPACE, value: "%s"}`,
		`"-e", "SKEMA_APP_ID=" + spec.HarnessID}`,
		"nothing to see here",
	} {
		if lineHasOldName(line) {
			t.Errorf("flagged a kept identifier: %q", line)
		}
	}
}
