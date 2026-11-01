package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Agent-written text cannot become Markdown in the report: no link, image,
// emphasis or HTML through a session title.
func TestReportTextCannotBecomeMarkdown(t *testing.T) {
	got := mdText("[click](http://evil.example) <img src=x> **loud** `x` # h")
	for _, bad := range []string{"[click](", "<img", "**loud**", "`x`"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q", bad, got)
		}
	}
}

func TestTheReportLeadsWithProblemsAndLeavesOutPrompts(t *testing.T) {
	homeTestWorld(t, true)
	now := time.Now()
	var b bytes.Buffer
	renderReportMarkdown(&b, buildReport(now, now.Add(-7*24*time.Hour)))
	md := b.String()
	for _, want := range []string{"# AI agents on ", "## Summary",
		"1 AI agent session running: 1 not marked as yours, 1 with permission prompts off, 1 waiting for a person.",
		"No baseline is recorded", "## Agents running now", "Claude Code background service",
		"No AI model wrote any of this report."} {
		if !strings.Contains(md, want) {
			t.Errorf("the report does not say %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "PRIVATE PROMPT TEXT") {
		t.Error("a session's last prompt is in the report")
	}
	if strings.Contains(md, "<script>") {
		t.Error("an agent's title went into the report as markup")
	}
}

func TestTheConsoleHandsTheReportOverAsAFile(t *testing.T) {
	homeTestWorld(t, true)
	u := uiTestServer(t)
	w := uiPost(t, u.handler(), "/machine/report", url.Values{}, uiSignedIn(t, u))
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") {
		t.Errorf("Content-Disposition %q", cd)
	}
	if !strings.Contains(w.Body.String(), "## Summary") {
		t.Errorf("body %q", firstLines(w.Body.String()))
	}
}
