package main

// "Add folders to your network" — DCN store onboarding, CLI-first.
//
// The production bastion is this binary (the enrollment flow installs it; there is
// no local dashboard), so the onboarding front door is a CLI verb:
//
//   privatae-bastion add-folder <path> [display name]
//
// The verb talks to the RUNNING daemon's loopback endpoint (POST /dcn/propose,
// OperatorSecret-guarded like /git-credential); the daemon validates the folder locally (this
// box can actually check, unlike the host) and forwards the draft over the live
// mTLS tunnel to the host's /api/network/nac/dcn/propose. The draft lands INERT —
// the user approves it in their host (Context Manager → Storage → Your network) with
// their step-up code. Nothing is granted from here, nothing is ever pre-selected,
// and skipping is first-class: the verb exists, run it or don't.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdAddFolder(host, path, name string) error {
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	if len(cfgs) == 0 {
		return fmt.Errorf("not paired yet — run `privatae-bastion pair <token>` first")
	}
	// Multi-homed boxes must NAME the host (0.10.0): guessing here is how a folder
	// ends up proposed to the wrong entity. One pairing needs no flag.
	var cfg *Config
	switch {
	case host != "":
		cfg, err = findPairing(cfgs, host)
		if err != nil {
			return err
		}
		if cfg == nil {
			return fmt.Errorf("no pairing matches --host '%s' — paired hosts:\n  %s",
				host, strings.Join(hostNames(cfgs), "\n  "))
		}
	case len(cfgs) == 1:
		cfg = cfgs[0]
	default:
		return fmt.Errorf("%d hosts are paired — say which one with --host:\n  privatae-bastion add-folder --host <host> %s\npaired hosts:\n  %s",
			len(cfgs), path, strings.Join(hostNames(cfgs), "\n  "))
	}
	abs, err := filepath.Abs(expandHome(path))
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("'%s' is not a directory on this machine", abs)
	}
	body, _ := json.Marshal(map[string]string{"root": abs, "display_name": name})
	req, err := http.NewRequest(http.MethodPost,
		"http://"+cfg.ListenAddr+"/dcn/propose", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.OperatorSecret)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("the bastion daemon isn't running — start it with `privatae-bastion run` (%w)", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("draft failed: %s", string(raw))
	}
	fmt.Printf(`Draft created for %s.

Your files stay on this machine. Privatae Host keeps only the index — a route map of
what exists and where — so your host can find things instantly. Content is read
on demand, only from folders you approve, and every read is logged for you.

Nothing is granted yet: approve the draft on your Host (Context Manager → Storage →
Your network) with your 6-digit code.
`, abs)
	return nil
}

func expandHome(p string) string {
	if len(p) >= 2 && p[:2] == "~/" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// dcnProposeLocal is the daemon-side loopback handler (mounted on the :7878 mux in
// cmdRun): validate locally, then forward the draft over the live tunnel with the
// bastion's bearer. The hostname sent as `server` is this box's — the same identity
// the heartbeat reports and the signed grant will name.
func dcnProposeLocal(upstream *http.Client, hostName, bearer, operatorSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !uiSecretMatches(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), operatorSecret) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var body struct {
			Root        string `json:"root"`
			DisplayName string `json:"display_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Root == "" {
			http.Error(w, `{"error":"root (a folder path) is required"}`, http.StatusBadRequest)
			return
		}
		abs, err := filepath.Abs(expandHome(body.Root))
		if err != nil {
			http.Error(w, `{"error":"bad path"}`, http.StatusBadRequest)
			return
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			http.Error(w, fmt.Sprintf(`{"error":"'%s' is not a directory on this machine"}`, abs),
				http.StatusBadRequest)
			return
		}
		// The bastion-authed draft lane (mirrors the heartbeat path family): the
		// host derives `server` from OUR bearer's heartbeat hostname — a bastion
		// can only propose folders on itself, so no server field is sent.
		payload, _ := json.Marshal(map[string]string{
			"root": abs, "display_name": body.DisplayName,
		})
		req, err := http.NewRequest(http.MethodPost,
			fmt.Sprintf("https://%s:8443/api/network/bastions/dcn-propose", hostName),
			bytes.NewReader(payload))
		if err != nil {
			http.Error(w, `{"error":"bad upstream request"}`, http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := upstream.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"could not reach your host: %s"}`, err),
				http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}
