package main

import (
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
// exceptions: a kept identifier is set aside only in Go code, outside its
// comments (goCodeAndComments). In a comment, a Markdown file, a script or
// any other file it is a hit like the bare word, and is described instead
// (the device-fingerprint prefix, fpSANPrefix in pair.go).
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

// hasOldName reports whether text carries the old name at all, kept
// identifiers included.
func hasOldName(text string) bool {
	return strings.Contains(strings.ToLower(text), oldName)
}

// goCodeAndComments splits Go source into its lines twice over: code[i] is
// line i with its comment text blanked, comments[i] the same line with
// everything but comment text blanked. String, raw string and rune literals
// are code, so a "//" inside one does not start a comment, and a raw string
// spanning lines stays code on every line it covers.
func goCodeAndComments(src string) (code, comments []string) {
	const (
		inCode = iota
		inLineComment
		inBlockComment
		inString
		inRawString
		inRune
	)
	codeB := []byte(src)
	commB := []byte(src)
	state := inCode
	for i := 0; i < len(src); i++ {
		c := src[i]
		isComment := false
		switch state {
		case inCode:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state, isComment = inLineComment, true
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				// Both opener bytes are taken here: the opener's '*' cannot
				// also start the closer, so "/*/" leaves the comment open.
				codeB[i], codeB[i+1] = ' ', ' '
				i++
				state = inBlockComment
				continue
			case c == '"':
				state = inString
			case c == '`':
				state = inRawString
			case c == '\'':
				state = inRune
			}
		case inLineComment:
			if c == '\n' {
				state = inCode
			} else {
				isComment = true
			}
		case inBlockComment:
			isComment = true
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				codeB[i], codeB[i+1] = ' ', ' '
				i++
				state = inCode
				continue
			}
		case inString, inRune:
			end := byte('"')
			if state == inRune {
				end = '\''
			}
			switch {
			case c == '\\' && i+1 < len(src) && src[i+1] != '\n':
				commB[i], commB[i+1] = ' ', ' '
				i++
				continue
			case c == end, c == '\n':
				state = inCode
			}
		case inRawString:
			if c == '`' {
				state = inCode
			}
		}
		if c == '\n' {
			continue
		}
		if isComment {
			codeB[i] = ' '
		} else {
			commB[i] = ' '
		}
	}
	return strings.Split(string(codeB), "\n"), strings.Split(string(commB), "\n")
}

// oldNameHits lists, as "line: text", every line of the published file rel
// that carries the old name. Kept identifiers are set aside only in the code
// of a Go file; in its comments and in every other file they count.
func oldNameHits(rel, src string) []string {
	lines := strings.Split(src, "\n")
	var hits []string
	if !strings.HasSuffix(rel, ".go") {
		for i, l := range lines {
			if hasOldName(l) {
				hits = append(hits, strconv.Itoa(i+1)+": "+strings.TrimSpace(l))
			}
		}
		return hits
	}
	code, comments := goCodeAndComments(src)
	for i, l := range lines {
		if lineHasOldName(code[i]) || hasOldName(comments[i]) {
			hits = append(hits, strconv.Itoa(i+1)+": "+strings.TrimSpace(l))
		}
	}
	return hits
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
		for _, h := range oldNameHits(rel, string(data)) {
			hits = append(hits, rel+":"+h)
		}
	}
	if len(hits) > 0 {
		t.Errorf("the old internal name appears in %d published lines. Reword prose and comments; an "+
			"identifier may be added to keptOldNames only when something outside this repository still "+
			"reads it, and is set aside only in Go code:\n  %s",
			len(hits), strings.Join(hits, "\n  "))
	}
}

// The check itself: it must catch the word in prose and in a longer name, and
// pass the kept identifiers.
func TestOldNameCheckCatchesProseAndPassesKeptIdentifiers(t *testing.T) {
	up := strings.ToUpper(oldName)
	title := strings.ToUpper(oldName[:1]) + oldName[1:]
	for _, line := range []string{
		"// see " + oldName + " for the rest",
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

// Where a kept identifier is set aside: in Go code only. In a Go comment, the
// changelog, any other Markdown file or a script it is a hit like the bare
// word. A "//" inside a string, a raw string spanning lines and an escaped
// quote do not move the line between code and comment.
func TestKeptIdentifiersAreSetAsideOnlyInGoCode(t *testing.T) {
	prefix := keptOldNames[len(keptOldNames)-1] // the fingerprint prefix
	env := keptOldNames[0]
	for _, c := range []struct {
		rel, src string
		hit      bool
	}{
		{"CHANGELOG.md", "- the fingerprint goes under `" + prefix + "<fp>`, as before\n", true},
		{"docs/claims.md", "the agent token is read from " + env + "\n", true},
		{"deploy/run.sh", "export " + env + "=x\n", true},
		{"a.go", "package a\n\n// names it " + prefix + "<fp>\n", true},
		{"a.go", "x := 1 /* " + env + " */\n", true},
		{"a.go", "x := 1 /*/ " + env + " */\n", true},
		{"a.go", "s := \"a\\\"b\" // " + env + "\n", true},
		{"a.go", "const p = \"" + prefix + "\"\n", false},
		{"a.go", "v := []string{\"" + env + "\"} // the host mints this tag\n", false},
		{"a.go", "u := \"https://example.com/" + env + "\"\n", false},
		{"a.go", "y := `\nname: x // " + env + "\n`\n", false},
		{"a.go", "r := '\"' + 1 // " + env + "\n", true},
	} {
		got := oldNameHits(c.rel, c.src)
		if (len(got) > 0) != c.hit {
			t.Errorf("%s %q: hits %q, want a hit: %v", c.rel, c.src, got, c.hit)
		}
	}
}
