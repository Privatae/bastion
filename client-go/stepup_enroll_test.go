package main

// stepup-enroll --console-only, the enrolment an installer runs in its one
// elevated step: the secret is shown only on a console and kept only in the
// system service's state, and both are checked before a secret exists.
// Every value here is invented.

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// enrolAt runs cmdStepupEnroll with the seams set and standard input and
// output replaced by pipes. answer gets what was printed so far and returns
// the line to type ("" types nothing and closes input).
func enrolAt(t *testing.T, console bool, serviceRefusal string, answer func(printed string) string) (string, error) {
	t.Helper()
	oldC, oldS := enrolConsole, enrolServiceState
	enrolConsole = func() bool { return console }
	enrolServiceState = func() string { return serviceRefusal }
	t.Cleanup(func() { enrolConsole, enrolServiceState = oldC, oldS })

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	printed := make(chan string, 1)
	go func() {
		var b strings.Builder
		r := bufio.NewReader(outR)
		typed := false
		for {
			line, err := r.ReadString('\n')
			b.WriteString(line)
			if !typed && strings.Contains(b.String(), "enter the key by hand:") {
				if a := answer(b.String()); a != "" {
					_, _ = io.WriteString(inW, a+"\n")
				}
				_ = inW.Close()
				typed = true
			}
			if err != nil {
				break
			}
		}
		printed <- b.String()
	}()
	err := cmdStepupEnroll("", false, true)
	_ = outW.Close()
	_ = inW.Close()
	select {
	case p := <-printed:
		return p, err
	case <-time.After(5 * time.Second):
		t.Fatal("enrolment output never finished")
	}
	return "", err
}

// keyFrom is the key printed after "enter the key by hand:".
func keyFrom(printed string) string {
	i := strings.Index(printed, "enter the key by hand:")
	if i < 0 {
		return ""
	}
	return strings.Fields(printed[i+len("enter the key by hand:"):])[0]
}

func filesHolding(t *testing.T, root, needle string) []string {
	t.Helper()
	var hits []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), needle) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

func TestEnrolmentKeepsTheSecretOnlyInTheServicesStepupFile(t *testing.T) {
	root := uiTestConfigDir(t)
	writePairing(t, pipeTestHost)
	printed, err := enrolAt(t, true, "", func(p string) string {
		raw, err := b32decode(keyFrom(p))
		if err != nil {
			t.Errorf("no key printed: %v", err)
			return ""
		}
		return hotp(raw, time.Now().Unix()/stepupPeriod)
	})
	if err != nil {
		t.Fatalf("enrol: %v\n%s", err, printed)
	}
	secret := keyFrom(printed)
	if len(secret) < 16 {
		t.Fatalf("no secret shown on the console:\n%s", printed)
	}
	cfgs, _ := loadPairings()
	want := filepath.Join(cfgs[0].dcnDir(), "stepup.json")
	hits := filesHolding(t, root, secret)
	if len(hits) != 1 || hits[0] != want {
		t.Fatalf("the secret must be in exactly one file, %s; found it in %v", want, hits)
	}
	if !stepupEnrolled(cfgs[0].dcnDir()) {
		t.Fatal("not enrolled after a confirmed code")
	}
}

func TestEnrolmentToAFileOrPipeOrOutsideTheServicesStateMakesNoSecret(t *testing.T) {
	for name, c := range map[string]struct {
		console bool
		refusal string
	}{
		"output to a file or pipe": {false, ""},
		"not the service's state":  {true, "this process does not administer the machine"},
	} {
		t.Run(name, func(t *testing.T) {
			root := uiTestConfigDir(t)
			writePairing(t, pipeTestHost)
			printed, err := enrolAt(t, c.console, c.refusal, func(string) string { return "123456" })
			if err == nil || !strings.Contains(err.Error(), "nothing was enrolled") {
				t.Fatalf("must refuse, got %v", err)
			}
			if strings.Contains(printed, "otpauth://") || strings.Contains(printed, "key by hand") {
				t.Fatalf("a secret was shown before the refusal:\n%s", printed)
			}
			if hits := filesHolding(t, root, "secret_b32"); len(hits) != 0 {
				t.Fatalf("a step-up file was written: %v", hits)
			}
		})
	}
}

func TestEnrolmentServiceStateRule(t *testing.T) {
	cases := []struct {
		goos               string
		installed, holding bool
		err                error
		ok                 bool
	}{
		{"windows", true, true, nil, true},
		{"windows", true, false, nil, false}, // unelevated: its own profile, readable by its own processes
		{"windows", false, true, nil, false}, // no service: an elevated admin's own profile
		{"windows", true, true, errTestNoService, false},
		{"darwin", true, true, nil, true},
		{"darwin", false, true, nil, false},
		{"linux", false, true, nil, true}, // root: the systemd unit's state
		{"linux", false, false, nil, false},
	}
	for _, c := range cases {
		got := enrolServiceStateRefusal(c.goos, c.installed, c.holding, c.err) == ""
		if got != c.ok {
			t.Errorf("%s installed=%v authority=%v err=%v: allowed=%v, want %v", c.goos, c.installed, c.holding, c.err, got, c.ok)
		}
	}
}
