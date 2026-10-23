package main

// The agent's credential for a harness run is a file in a folder mounted into
// the container. No other local user may reach either: as root the bastion
// hands both to the container's user, owner-only; as anyone else it opens them
// for that user, inside a folder only the bastion can enter.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTheHarnessCredentialIsReadableOnlyByTheContainersUser(t *testing.T) {
	// A stand-in runtime: on `run` it records the mode and owner of the folder
	// the credential folder sits in, of that folder and of the file, then
	// fails, so the run stops there.
	bin := t.TempDir()
	record := filepath.Join(bin, "record")
	rt := filepath.Join(bin, "runtime")
	script := "#!/bin/sh\n[ \"$1\" = run ] || exit 1\nfor a; do case \"$a\" in *:/home/privatae/.claude) d=${a%:/home/privatae/.claude};; esac; done\n" +
		"[ -n \"$d\" ] && stat -c '%a %u %g' \"$(dirname \"$d\")\" \"$d\" \"$d/.credentials.json\" > " + record + "\nexit 1\n"
	if err := os.WriteFile(rt, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	spec := harnessSpec{HarnessID: "h1", Image: "harness:test", AgentCreds: `{"claudeAiOauth":{}}`}
	if _, err := driveHarnessAgent(rt, t.TempDir(), spec, 1); err == nil {
		t.Fatal("the stand-in runtime fails the start; the run must report it")
	}
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the credential folder was not mounted: %v", err)
	}
	self := strconv.Itoa(os.Geteuid()) + " " + strconv.Itoa(os.Getegid())
	want := "700 " + self + "\n777 " + self + "\n666 " + self
	if os.Geteuid() == 0 {
		want = "700 " + self + "\n700 10005 10005\n600 10005 10005" // the harness image's user
	}
	if strings.TrimSpace(string(got)) != want {
		t.Fatalf("enclosing folder, folder, then file: want %q, got %q", want, strings.TrimSpace(string(got)))
	}
}
