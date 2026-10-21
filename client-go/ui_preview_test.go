package main

// Renders the page and its assets to $UI_PREVIEW_DIR so a browser can screenshot
// it. Skipped unless that is set, so it costs the suite nothing.
//
// It is kept rather than thrown away because the remaining phases of
// the local UI are visual work, and "does this look right"
// is a question no assertion answers. A fixed three-pairing fixture means two
// screenshots are comparable.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderAPreview(t *testing.T) {
	dir := os.Getenv("UI_PREVIEW_DIR")
	if dir == "" {
		t.Skip("UI_PREVIEW_DIR unset")
	}
	uiTestConfigDir(t)
	d, _ := pairingsDir()
	_ = os.MkdirAll(d, 0o700)
	for _, p := range []struct{ host, addr, state string }{
		{"259c83f46775ec66.host.privatae.ai", "127.0.0.1:7878", pairingActive},
		{"8abb770bbfde71d0.host.privatae.ai", "127.0.0.1:7879", pairingActive},
		{"99dab9c47d60edff.host.privatae.ai", "127.0.0.1:7880", pairingPending},
	} {
		b := []byte(`{"host_name":"` + p.host + `","listen_addr":"` + p.addr +
			`","bastion_tunnel_ip":"fd00:9::a:1","state":"` + p.state +
			`","first_seen":"2026-09-01T00:00:00Z"}`)
		_ = os.WriteFile(filepath.Join(d, p.host+".json"), b, 0o600)
	}

	// One pending approval on the first host, so the preview carries the part of
	// the page that is actually waiting on somebody.
	dcn := filepath.Join(t.TempDir(), "dcn")
	_ = os.MkdirAll(dcn, 0o700)
	first := filepath.Join(d, "259c83f46775ec66.host.privatae.ai.json")
	if b, err := os.ReadFile(first); err == nil {
		s := strings.TrimSuffix(string(b), "}") + `,"dcn_dir":` + jsonQuote(dcn) + `}`
		_ = os.WriteFile(first, []byte(s), 0o600)
	}
	_ = stepupSave(dcn, &stepupFile{
		SecretB32: uiTestSecret, EnrolledAt: "2026-08-29T00:00:00Z", LastCounter: -1})
	_ = requestsSave(dcn, map[string]stepupRequest{
		"7f3a91c40de2bb18": {
			Purpose: "dcn_store_grant|Documents|read",
			Details: map[string]any{
				"kind": "dcn_store_grant", "root": "~/Documents",
				"mask": []any{"read", "index"}, "excludes": []any{".ssh", ".env"},
				"sweep": "nightly", "ttl_days": float64(30),
				"display_name": "Documents",
			},
			At: uiTestRecently(), State: "pending",
		},
	})

	u, err := newUIServer("7877", "s")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(dir, 0o755)
	var sb strings.Builder
	if err := u.tpl.ExecuteTemplate(&sb, "page.html", collectUIStatus()); err != nil {
		t.Fatal(err)
	}
	html := strings.ReplaceAll(sb.String(), "/assets/", "./")
	_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0o644)
	for _, n := range []string{"app.css", "htmx.min.js"} {
		b, err := uiStaticFS.ReadFile("uiassets/" + n)
		if err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(dir, n), b, 0o644)
	}
	t.Logf("wrote %s", dir)
}
