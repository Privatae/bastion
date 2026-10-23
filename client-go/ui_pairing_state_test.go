package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pairing whose file this build will not serve reads "invalid" on the
// console, as it does on the setup page and in `status`, even when the state
// stored in the file is empty, the old spelling of active.
func TestTheConsoleShowsAPairingThatIsNotServedAsInvalid(t *testing.T) {
	const host = "unserved.host.privatae.ai"
	uiTestConfigDir(t)
	pd, err := pairingsDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pd, 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(Config{HostName: host, ListenAddr: "127.0.0.1:59999",
		Endpoint: "203.0.113.7:51820\nallowed_ip=::/0"}) // one the endpoint check refuses
	if err := os.WriteFile(filepath.Join(pd, host+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range collectUIStatus().Pairings {
		got = append(got, p.Host+"="+p.State)
	}
	if want := host + "=" + pairingInvalid; len(got) != 1 || got[0] != want {
		t.Errorf("the console reads %v, want [%s]", got, want)
	}
	u := uiTestServer(t)
	body := uiSetupGet(t, u.handler(), "/fragments/status", uiSignedIn(t, u)).Body.String()
	if !strings.Contains(body, "invalid, not served") {
		t.Errorf("the console page does not say the pairing is not served: %q", body)
	}
}
