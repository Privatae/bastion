package main

// pairing_retry.go — each pairing runs on its own.
//
// Until 0.63.0 one pairing's fatal error (a port it could not bind, a lane
// that would not come up, a bad certificate in its file) went to cmdRun and
// stopped the whole daemon, so every other Host on the machine went dark with
// it, and on Windows the service manager restarted all of them into the same
// failure every five seconds. Now that error stops that pairing alone. It is
// reported (the log, the machine's events, `status`), and the supervisor
// (run.go superviseOnce) starts it again by itself after a pause that doubles
// from supervisePeriod up to retryMaxPause, the other pairings serving all
// along. A run that stays up for retryResetAfter clears the record.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	retryMaxPause   = 5 * time.Minute
	retryResetAfter = 2 * time.Minute
)

// pairingFailure is one pairing's last fatal error, as status reads it.
type pairingFailure struct {
	Error   string `json:"error"`
	At      string `json:"at"`
	NextTry string `json:"next_try"`
	Tries   int    `json:"tries"`
}

var pairingRetry = struct {
	sync.Mutex
	next  map[string]time.Time
	tries map[string]int
}{next: map[string]time.Time{}, tries: map[string]int{}}

func pairingFailuresPath() (string, error) {
	d, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "pairing_failures.json"), nil
}

// loadPairingFailures is the record status reads; empty when there is none.
func loadPairingFailures() map[string]pairingFailure {
	out := map[string]pairingFailure{}
	p, err := pairingFailuresPath()
	if err != nil {
		return out
	}
	if raw, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

func savePairingFailuresLocked(m map[string]pairingFailure) {
	p, err := pairingFailuresPath()
	if err != nil {
		return
	}
	if len(m) == 0 {
		_ = os.Remove(p)
		return
	}
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = atomicWrite(p, b)
	}
}

// retryPause is the pause before try n+1 after n failures in a row.
func retryPause(n int) time.Duration {
	d := supervisePeriod
	for i := 1; i < n && d < retryMaxPause; i++ {
		d *= 2
	}
	return min(d, retryMaxPause)
}

// pairingFailed records host's fatal error and when it is tried again, and
// says so. ranFor is how long the run had been up: one that served for
// retryResetAfter starts the count again.
func pairingFailed(host string, err error, ranFor time.Duration) {
	pairingRetry.Lock()
	defer pairingRetry.Unlock()
	if ranFor >= retryResetAfter {
		pairingRetry.tries[host] = 0
	}
	pairingRetry.tries[host]++
	n := pairingRetry.tries[host]
	now := time.Now()
	next := now.Add(retryPause(n))
	pairingRetry.next[host] = next
	m := loadPairingFailures()
	m[host] = pairingFailure{Error: err.Error(), At: now.UTC().Format(time.RFC3339),
		NextTry: next.UTC().Format(time.RFC3339), Tries: n}
	savePairingFailuresLocked(m)
	why := strings.TrimRight(strings.TrimSpace(err.Error()), ".")
	line := fmt.Sprintf("stopped: %s. The other Hosts go on being served; it is tried again by itself at %s.",
		why, next.Local().Format("15:04:05"))
	fmt.Printf("[%s] %s\n", host, line)
	recordLocalEvent("pairing", host+" "+line)
}

// pairingRetryDue: host has no failure pending a pause, or its pause is over.
func pairingRetryDue(host string) bool {
	pairingRetry.Lock()
	defer pairingRetry.Unlock()
	next, ok := pairingRetry.next[host]
	return !ok || !time.Now().Before(next)
}

// pairingRecovered clears host's record: its run has stayed up, or it ended
// cleanly.
func pairingRecovered(host string) {
	pairingRetry.Lock()
	defer pairingRetry.Unlock()
	if _, ok := pairingRetry.next[host]; !ok {
		return
	}
	delete(pairingRetry.next, host)
	delete(pairingRetry.tries, host)
	m := loadPairingFailures()
	if _, ok := m[host]; ok {
		delete(m, host)
		savePairingFailuresLocked(m)
	}
}
