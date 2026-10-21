package main

// Tests for the pull half of the observe family: the endpoints file and its
// every refusal, the three ops driven end to end through the real dispatcher,
// and the heartbeat's `alerts` contract.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// withEndpointsFile writes one observe-endpoints.json and points the loader at
// it for the duration of the test.
func withEndpointsFile(t *testing.T, content string) func() {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observe-endpoints.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := observeEndpointsPath
	observeEndpointsPath = path
	return func() { observeEndpointsPath = orig }
}

// withNoEndpointsFile points the loader at a path that does not exist, so a box
// running the suite cannot leak its own real file into a test.
func withNoEndpointsFile(t *testing.T) func() {
	t.Helper()
	orig := observeEndpointsPath
	observeEndpointsPath = filepath.Join(t.TempDir(), "absent.json")
	return func() { observeEndpointsPath = orig }
}

// ── the endpoints file ───────────────────────────────────────────────────────

// The allow list is the INVERSE of observe:net's. Every address class that op
// refuses, this one must accept — and the public addresses it exists to probe
// are exactly what this one must refuse.
func TestObserveEndpointAllowedIsTheInverseOfObserveNet(t *testing.T) {
	private := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"100.64.0.1", "100.127.255.255", "169.254.169.254", "0.0.0.0", "::1", "::", "fc00::1",
		"fd12::1", "fe80::1", "::ffff:10.0.0.1", "10.99.1.1"}
	for _, ip := range private {
		a := netip.MustParseAddr(ip)
		if !observeEndpointAllowed(a) {
			t.Errorf("%s must be ALLOWED here — it is the box's own neighbourhood", ip)
		}
		if isPublicAddr(a) {
			t.Errorf("%s: the two checks disagree; they must be exact opposites", ip)
		}
	}
	for _, ip := range []string{"203.0.113.10", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111"} {
		a := netip.MustParseAddr(ip)
		if observeEndpointAllowed(a) {
			t.Errorf("%s is PUBLIC and must be refused — this file may not make the box fetch the internet", ip)
		}
	}
}

func TestObserveEndpointsFileParsing(t *testing.T) {
	// A stubbed resolver so the hostname cases need no DNS.
	orig := netResolve
	netResolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		switch host {
		case "alerts.internal":
			return []netip.Addr{netip.MustParseAddr("10.99.1.1")}, nil
		case "split.internal":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("203.0.113.10")}, nil
		case "public.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		case "empty.internal":
			return nil, nil
		}
		return nil, errors.New("no such host")
	}
	defer func() { netResolve = orig }()

	cases := []struct {
		name    string
		content string
		wantErr string // "" = accepted; otherwise a substring the message must carry
		check   func(t *testing.T, e observeEndpoints)
	}{
		{name: "all three, IP literals",
			content: `{"alertmanager":"http://10.99.1.1:9093","prometheus":"http://10.99.1.2:9090","loki":"http://10.99.1.3:3100"}`,
			check: func(t *testing.T, e observeEndpoints) {
				if e.Alertmanager != "http://10.99.1.1:9093" || e.Prometheus != "http://10.99.1.2:9090" ||
					e.Loki != "http://10.99.1.3:3100" {
					t.Fatalf("%+v", e)
				}
			}},
		{name: "loopback is allowed", content: `{"loki":"http://127.0.0.1:3100"}`},
		{name: "ULA is allowed", content: `{"loki":"http://[fd00:1::10]:3100"}`},
		{name: "link-local is allowed", content: `{"loki":"http://169.254.1.1:3100"}`},
		{name: "CGNAT is allowed", content: `{"loki":"http://100.64.0.1:3100"}`},
		{name: "https is allowed", content: `{"prometheus":"https://10.0.0.9:9090"}`},
		{name: "a private hostname is allowed", content: `{"alertmanager":"http://alerts.internal:9093"}`},
		{name: "one key only, the rest empty", content: `{"alertmanager":"http://10.99.1.1:9093"}`,
			check: func(t *testing.T, e observeEndpoints) {
				if e.Prometheus != "" || e.Loki != "" {
					t.Fatalf("%+v", e)
				}
			}},
		{name: "a trailing slash normalizes", content: `{"loki":"http://10.0.0.1:3100/"}`,
			check: func(t *testing.T, e observeEndpoints) {
				if e.Loki != "http://10.0.0.1:3100" {
					t.Fatalf("%q", e.Loki)
				}
			}},

		{name: "a public literal is refused", content: `{"alertmanager":"http://203.0.113.10:9093"}`,
			wantErr: "alertmanager: 203.0.113.10 is a public address"},
		{name: "a public hostname is refused", content: `{"loki":"http://public.example:3100"}`,
			wantErr: "loki: 203.0.113.10 is a public address"},
		{name: "one public record refuses the whole name", content: `{"prometheus":"http://split.internal:9090"}`,
			wantErr: "prometheus: 203.0.113.10 is a public address"},
		{name: "an unresolvable name is refused", content: `{"loki":"http://nx.internal:3100"}`,
			wantErr: "loki: resolve nx.internal"},
		{name: "a name with no addresses is refused", content: `{"loki":"http://empty.internal:3100"}`,
			wantErr: "loki: resolve empty.internal: no addresses"},
		{name: "a non-http scheme is refused", content: `{"loki":"ftp://10.0.0.1:3100"}`,
			wantErr: `loki: scheme must be http or https, got "ftp"`},
		{name: "file:// is refused", content: `{"prometheus":"file:///etc/shadow"}`,
			wantErr: "prometheus: scheme must be http or https"},
		// A bare host:port never gets as far as the scheme check — url.Parse
		// rejects it outright — but it is refused, and the message names the key.
		{name: "no scheme is refused", content: `{"loki":"10.0.0.1:3100"}`,
			wantErr: "loki: not a URL"},
		{name: "a bare hostname is refused", content: `{"loki":"10.0.0.1"}`,
			wantErr: "loki: scheme must be http or https"},
		{name: "credentials in the URL are refused", content: `{"loki":"http://u:p@10.0.0.1:3100"}`,
			wantErr: "loki: credentials in the URL"},
		{name: "a path is refused", content: `{"alertmanager":"http://10.0.0.1:9093/api/v2"}`,
			wantErr: "alertmanager: the endpoint is a base URL — no path"},
		{name: "a query is refused", content: `{"loki":"http://10.0.0.1:3100?x=1"}`,
			wantErr: "loki: the endpoint is a base URL — no query"},
		{name: "a bad port is refused", content: `{"loki":"http://10.0.0.1:notaport"}`,
			wantErr: "loki"},
		{name: "no host is refused", content: `{"loki":"http://"}`,
			wantErr: "loki: no host"},
		{name: "malformed JSON is refused", content: `{"loki":`,
			wantErr: "observe-endpoints.json:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer withEndpointsFile(t, c.content)()
			e, err := loadObserveEndpoints(context.Background())
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("must be accepted, got %v", err)
				}
				if c.check != nil {
					c.check(t, e)
				}
				return
			}
			if err == nil {
				t.Fatalf("must be refused, got %+v", e)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("the message must name the key and the reason\n got: %v\nwant: %q", err, c.wantErr)
			}
			// A refusal returns NOTHING — never a half-loaded file where the
			// keys before the bad one are still live.
			if e.Alertmanager != "" || e.Prometheus != "" || e.Loki != "" {
				t.Fatalf("a refused file must yield no endpoints at all: %+v", e)
			}
		})
	}
}

// An absent file is UNCONFIGURED, not an error: the same distinction
// observe:k8s makes about a missing kubeconfig.
func TestObserveEndpointsAbsentIsUnconfiguredNotAnError(t *testing.T) {
	defer withNoEndpointsFile(t)()
	if _, err := loadObserveEndpoints(context.Background()); !errors.Is(err, errEndpointsAbsent) {
		t.Fatalf("absent must be the sentinel, got %v", err)
	}
	base, unconfigured, err := observeEndpointFor(context.Background(), observeKeyAlertmanager)
	if err != nil || base != "" || !strings.HasPrefix(unconfigured, "unconfigured: no endpoints file") {
		t.Fatalf("base=%q unconfigured=%q err=%v", base, unconfigured, err)
	}
	// A file that exists but names a different service: still unconfigured for
	// this key, and the message says WHICH key is missing.
	defer withEndpointsFile(t, `{"loki":"http://127.0.0.1:3100"}`)()
	_, unconfigured, err = observeEndpointFor(context.Background(), observeKeyAlertmanager)
	if err != nil || !strings.Contains(unconfigured, `names no "alertmanager"`) {
		t.Fatalf("unconfigured=%q err=%v", unconfigured, err)
	}
}

// ── fixtures ─────────────────────────────────────────────────────────────────

// fxAlerts is three active alerts of mixed severity, in the shape Alertmanager
// v2 actually returns (confirmed against a live Alertmanager). Deliberately
// NOT in severity order on the wire, so the ordering under test is this box's
// and not the server's.
const fxAlerts = `[
 {"fingerprint":"aaa1","labels":{"alertname":"KubeMemoryOvercommit","severity":"warning","cluster":"platform"},
  "startsAt":"2026-09-14T08:12:16.597Z","status":{"state":"active"}},
 {"fingerprint":"bbb2","labels":{"alertname":"FleetUnitFailed","severity":"critical","unit":"edge-checker.service"},
  "startsAt":"2026-09-15T01:00:00.000Z","status":{"state":"active"}},
 {"fingerprint":"ccc3","labels":{"alertname":"Watchdog","severity":"none"},
  "startsAt":"2026-09-16T02:00:00.000Z","status":{"state":"active"}}
]`

// fakeMonitoring serves the three upstreams on one loopback httptest server and
// writes an endpoints file naming it. Loopback is allowed here by design, which
// is what makes an end-to-end test of these ops possible at all.
func fakeMonitoring(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	restore := withEndpointsFile(t, fmt.Sprintf(
		`{"alertmanager":%q,"prometheus":%q,"loki":%q}`, srv.URL, srv.URL, srv.URL))
	t.Cleanup(restore)
	return srv
}

// ── observe:alerts ───────────────────────────────────────────────────────────

func TestObserveAlertsEndToEnd(t *testing.T) {
	var asked string
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RequestURI()
		_, _ = w.Write([]byte(fxAlerts))
	})
	out, errOut, code := driveObserve(t, "observe:alerts", nil)
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if asked != alertmanagerAlertsPath {
		t.Fatalf("the op must ask the v2 path verbatim: %q", asked)
	}
	// All four v2 filter flags are named — see
	// TestObserveAlertsExcludesSilencedAndInhibited for why active=true alone
	// is not a narrowing.
	for _, want := range []string{"active=true", "silenced=false", "inhibited=false", "unprocessed=false"} {
		if !strings.Contains(asked, want) {
			t.Fatalf("missing %q from %q", want, asked)
		}
	}
	var rep alertsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.Source != "alertmanager" || rep.Count != 3 || len(rep.Alerts) != 3 || rep.Truncated {
		t.Fatalf("%+v", rep)
	}
	byFP := map[string]observedAlert{}
	for _, a := range rep.Alerts {
		byFP[a.Fingerprint] = a
	}
	if a := byFP["bbb2"]; a.Alertname != "FleetUnitFailed" || a.Severity != "critical" ||
		a.State != "active" || a.StartsAt != "2026-09-15T01:00:00.000Z" ||
		a.Labels["unit"] != "edge-checker.service" {
		t.Fatalf("the typed row must carry the labels through: %+v", a)
	}
}

// The summary the heartbeat carries: counts by severity, the OLDEST start, and
// the fingerprints critical first.
func TestAlertsSummaryCountsAndOrder(t *testing.T) {
	rep, err := parseAlerts([]byte(fxAlerts))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 16, 3, 0, 0, 0, time.UTC)
	s := summarizeAlerts(rep, now)
	if s.Firing != 3 {
		t.Fatalf("firing counts EVERY active alert, whatever its severity: %+v", s)
	}
	if s.Critical != 1 || s.Warning != 1 {
		t.Fatalf("severity buckets: %+v", s)
	}
	if s.Since == nil || *s.Since != "2026-09-14T08:12:16Z" {
		t.Fatalf("since is the OLDEST startsAt: %v", s.Since)
	}
	if s.At != "2026-09-16T03:00:00Z" {
		t.Fatalf("at is this refresh: %q", s.At)
	}
	// critical, then warning, then the rest — never the server's order.
	if got := strings.Join(s.Fingerprints, ","); got != "bbb2,aaa1,ccc3" {
		t.Fatalf("fingerprints must be critical first, got %q", got)
	}
	// An empty Alertmanager summarizes to zeros with a null `since` — a real
	// state, distinct from the key being absent.
	empty := summarizeAlerts(alertsReport{Alerts: []observedAlert{}}, now)
	if empty.Firing != 0 || empty.Since != nil || len(empty.Fingerprints) != 0 {
		t.Fatalf("%+v", empty)
	}
	b, _ := json.Marshal(empty)
	if !strings.Contains(string(b), `"since":null`) {
		t.Fatalf("since must serialize as null, not an empty string: %s", b)
	}
}

// Both caps, and both reported.
func TestObserveAlertsTruncation(t *testing.T) {
	big := strings.Repeat("x", observeLabelValueCap+1)
	var rows []string
	for i := 0; i < observeAlertCap+50; i++ {
		rows = append(rows, fmt.Sprintf(
			`{"fingerprint":"fp%03d","labels":{"alertname":"A","severity":"critical","blob":%q},`+
				`"startsAt":"2026-09-15T01:00:00Z","status":{"state":"active"}}`, i, big))
	}
	rep, err := parseAlerts([]byte("[" + strings.Join(rows, ",") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Count != observeAlertCap || len(rep.Alerts) != observeAlertCap {
		t.Fatalf("the alert cap must hold: %d", rep.Count)
	}
	if !rep.Truncated {
		t.Fatal("a cut must be reported, never silent")
	}
	if _, present := rep.Alerts[0].Labels["blob"]; present {
		t.Fatalf("a label value over %d bytes must be dropped: %+v", observeLabelValueCap, rep.Alerts[0].Labels)
	}
	if len(rep.Alerts[0].DroppedLabels) != 1 || rep.Alerts[0].DroppedLabels[0] != "blob" {
		t.Fatalf("a dropped label must be NAMED, or absent reads as unset: %+v", rep.Alerts[0].DroppedLabels)
	}
	if rep.Alerts[0].Labels["alertname"] != "A" || rep.Alerts[0].Severity != "critical" {
		t.Fatalf("the labels under the cap ride through: %+v", rep.Alerts[0])
	}
	// The summary never carries more than twenty fingerprints — and `firing`
	// is the REAL number, not the row cap. See
	// TestAlertCountsAreNotCappedWithTheRows for why that distinction matters.
	s := summarizeAlerts(rep, time.Now())
	if len(s.Fingerprints) != alertsFingerprintCap {
		t.Fatalf("fingerprints=%d", len(s.Fingerprints))
	}
	if s.Firing != observeAlertCap+50 || rep.ActiveTotal != observeAlertCap+50 {
		t.Fatalf("firing must be the true count, not the row cap: firing=%d active_total=%d",
			s.Firing, rep.ActiveTotal)
	}
}

// ── observe:metrics ──────────────────────────────────────────────────────────

func TestObserveMetricsFixedTable(t *testing.T) {
	var asked string
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.Query().Get("query")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
		 {"metric":{"__name__":"up","job":"kubelet","node":"example-host"},"value":[1789525594.139,"1"]},
		 {"metric":{"__name__":"up","job":"kubelet","node":"example-host-2"},"value":[1789525594.139,"0"]}]}}`))
	})
	out, errOut, code := driveObserve(t, "observe:metrics", []string{"up"})
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if asked != "up" {
		t.Fatalf("the box owns the PromQL: %q", asked)
	}
	var rep metricsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !rep.Supported || rep.Name != "up" || rep.Query != "up" || rep.Count != 2 {
		t.Fatalf("%+v", rep)
	}
	if rep.Series[1].Value != "0" || rep.Series[1].Labels["node"] != "example-host-2" || rep.Series[1].TS == 0 {
		t.Fatalf("%+v", rep.Series[1])
	}

	// Every name in the table reaches the wire as the box's own query, and the
	// query that goes out is never the caller's bytes.
	for _, name := range metricNames() {
		if _, _, code := driveObserve(t, "observe:metrics", []string{name}); code != 0 {
			t.Fatalf("%s: exit %d", name, code)
		}
		if asked != observeMetricQueries[name] {
			t.Fatalf("%s sent %q, want %q", name, asked, observeMetricQueries[name])
		}
	}
}

func TestObserveMetricsUnknownNameIsRefusedWithTheKnownOnes(t *testing.T) {
	defer withNoEndpointsFile(t)()
	// The refusal happens BEFORE any endpoint is consulted, so it works on a
	// box with no endpoints file at all — and nothing leaves the process.
	orig := observeHTTPGet
	observeHTTPGet = func(_ context.Context, rawURL string) ([]byte, int, error) {
		t.Fatalf("an unknown name reached the network: %q", rawURL)
		return nil, 0, nil
	}
	defer func() { observeHTTPGet = orig }()

	for _, bad := range []string{"node_cpu; rm -rf /", "sum(rate(x[5m]))", "", "UP", "up "} {
		out, errOut, code := driveObserve(t, "observe:metrics", []string{bad})
		if code == 0 {
			t.Fatalf("%q was ACCEPTED — the table is the wall: %s", bad, out)
		}
		if !strings.Contains(errOut, "unknown metric name") {
			t.Fatalf("%q: %q", bad, errOut)
		}
		for _, name := range metricNames() {
			if !strings.Contains(errOut, name) {
				t.Fatalf("the refusal must list every known name; %q missing from %q", name, errOut)
			}
		}
	}
	// Wrong arity refuses too, and still names the table.
	for _, args := range [][]string{nil, {"up", "extra"}} {
		_, errOut, code := driveObserve(t, "observe:metrics", args)
		if code == 0 || !strings.Contains(errOut, "exactly one argument") {
			t.Fatalf("args=%v code=%d err=%q", args, code, errOut)
		}
	}
}

// A Prometheus that rejects the query is an ERROR, never an empty series list:
// "no series" and "the query was refused" may not read the same.
func TestObserveMetricsRejectedQueryIsNotAnEmptyResult(t *testing.T) {
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`))
	})
	_, errOut, code := driveObserve(t, "observe:metrics", []string{"up"})
	if code == 0 || !strings.Contains(errOut, "HTTP 400") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

// ── observe:logs ─────────────────────────────────────────────────────────────

func TestObserveLogsEndToEndNewestLast(t *testing.T) {
	var q url.Values
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		// Two streams, interleaved and out of order on the wire.
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
		 {"stream":{"unit":""},"values":[["300","third"],["100","first"]]},
		 {"stream":{"unit":""},"values":[["200","second"]]}]}}`))
	})
	out, errOut, code := driveObserve(t, "observe:logs", []string{"kernel"})
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if got := q.Get("query"); got != mustSelector(t, "kernel") {
		t.Fatalf("the box owns the LogQL: %q", got)
	}
	if q.Get("direction") != "backward" {
		t.Fatalf("Loki is asked backward so a server-side limit keeps the NEWEST: %q", q.Get("direction"))
	}
	var rep logsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if rep.Minutes != observeLogMinutesDefault || rep.Name != "kernel" || rep.Lines != 3 || rep.Truncated {
		t.Fatalf("%+v", rep)
	}
	lines := strings.Split(strings.TrimRight(rep.Log, "\n"), "\n")
	if !strings.HasSuffix(lines[0], "first") || !strings.HasSuffix(lines[2], "third") {
		t.Fatalf("newest last, across streams: %q", rep.Log)
	}
}

func TestObserveLogsMinutes(t *testing.T) {
	var q url.Values
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	})
	// Accepted: the whole 1..60 boundary, and the window actually asked for.
	for _, m := range []string{"1", "15", "60"} {
		out, errOut, code := driveObserve(t, "observe:logs", []string{"sshd", m})
		if code != 0 {
			t.Fatalf("%s minutes: exit %d %s", m, code, errOut)
		}
		var rep logsReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		start, end := mustNano(t, q.Get("start")), mustNano(t, q.Get("end"))
		want := time.Duration(rep.Minutes) * time.Minute
		if got := time.Duration(end - start); got != want {
			t.Fatalf("%s minutes: asked Loki for %v, want %v", m, got, want)
		}
	}
	// Refused, never CLAMPED: a host that asked for 600 minutes and silently
	// got 60 would draw a ten-hour conclusion from one hour of logs.
	for _, m := range []string{"0", "61", "600", "-5", "abc", "15.5", ""} {
		_, errOut, code := driveObserve(t, "observe:logs", []string{"sshd", m})
		if code == 0 {
			t.Fatalf("%q minutes was accepted", m)
		}
		if !strings.Contains(errOut, "minutes must be") {
			t.Fatalf("%q: %q", m, errOut)
		}
	}
	// Unknown name: refused with the known ones listed, same as metrics.
	_, errOut, code := driveObserve(t, "observe:logs", []string{`{job="everything"}`})
	if code == 0 || !strings.Contains(errOut, "unknown log name") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	for _, name := range logNames() {
		if !strings.Contains(errOut, name) {
			t.Fatalf("%q missing from the refusal %q", name, errOut)
		}
	}
}

func mustNano(t *testing.T, s string) int64 {
	t.Helper()
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("bad nano %q: %v", s, err)
	}
	return n
}

// 200 KB, the same cap `ufw status verbose` is held to — and the OLDEST lines
// are the ones that go, because the answer ends on the newest.
func TestObserveLogsByteCap(t *testing.T) {
	line := strings.Repeat("y", 1024)
	var vals []string
	for i := 0; i < 400; i++ { // ~400 KB, twice the cap
		vals = append(vals, fmt.Sprintf(`["%d","%04d %s"]`, (i+1)*1000, i, line))
	}
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
		 {"stream":{},"values":[` + strings.Join(vals, ",") + `]}]}}`))
	})
	out, errOut, code := driveObserve(t, "observe:logs", []string{"bastion"})
	if code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	var rep logsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Log) > observeTextCap {
		t.Fatalf("log is %d bytes, cap is %d", len(rep.Log), observeTextCap)
	}
	if !rep.Truncated {
		t.Fatal("a cut must be reported")
	}
	if !strings.HasSuffix(strings.TrimRight(rep.Log, "\n"), "0399 "+line) {
		t.Fatalf("the NEWEST line must survive the cut; log ends %q", rep.Log[len(rep.Log)-40:])
	}
	if strings.Contains(rep.Log, "0000 ") {
		t.Fatal("the oldest line should have been the one dropped")
	}
}

// ── unconfigured, and the wall ───────────────────────────────────────────────

// Absent file: all three report the observe:k8s shape at the observe:k8s exit
// code, and none of them touches the network.
func TestObservePullUnconfiguredShape(t *testing.T) {
	defer withNoEndpointsFile(t)()
	orig := observeHTTPGet
	observeHTTPGet = func(_ context.Context, rawURL string) ([]byte, int, error) {
		t.Fatalf("an unconfigured op dialled %q", rawURL)
		return nil, 0, nil
	}
	defer func() { observeHTTPGet = orig }()

	for op, args := range map[string][]string{
		"observe:alerts":  nil,
		"observe:metrics": {"up"},
		"observe:logs":    {"kernel"},
	} {
		out, errOut, code := driveObserve(t, op, args)
		if code != 0 {
			t.Fatalf("%s: unconfigured is a REPORT, not a refusal — observe:k8s exits 0: %d %q", op, code, errOut)
		}
		var rep struct {
			Supported bool   `json:"supported"`
			Reason    string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%s: %v: %s", op, err, out)
		}
		if rep.Supported {
			t.Fatalf("%s: %s", op, out)
		}
		if !strings.Contains(rep.Reason, "unconfigured") || !strings.Contains(rep.Reason, observeEndpointsPath) {
			t.Fatalf("%s: the reason must name the file the admin has to place: %q", op, rep.Reason)
		}
	}
	// A file that is there and WRONG is a different answer: a refusal that
	// names the key, so the admin knows which line to fix.
	defer withEndpointsFile(t, `{"prometheus":"http://8.8.8.8:9090"}`)()
	_, errOut, code := driveObserve(t, "observe:metrics", []string{"up"})
	if code != 2 || !strings.Contains(errOut, "prometheus:") || !strings.Contains(errOut, "public address") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

// ── the heartbeat contract ───────────────────────────────────────────────────

// ABSENT is not ZERO. The key is missing until a refresh has succeeded, and a
// zero summary — a real all-clear — is a different thing on the wire.
func TestHeartbeatAlertsAbsentIsNotZero(t *testing.T) {
	alertsMu.Lock()
	alertsLast = nil
	alertsMu.Unlock()
	defer func() {
		alertsMu.Lock()
		alertsLast = nil
		alertsMu.Unlock()
	}()
	defer withNoEndpointsFile(t)()

	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if _, present := m["alerts"]; present {
		t.Fatalf("with no alertmanager configured the key must be ABSENT: %s", raw)
	}
	// A refresh against a box with no endpoints file publishes nothing at all.
	refreshAlerts(context.Background())
	if alertsPayload() != nil {
		t.Fatal("an unconfigured refresh must publish nothing")
	}
}

// The exact shape the host side is built against, served from the cache — a
// beat never waits on the fetch.
func TestHeartbeatAlertsContract(t *testing.T) {
	calls := 0
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(fxAlerts))
	})
	alertsMu.Lock()
	alertsLast = nil
	alertsMu.Unlock()
	defer func() {
		alertsMu.Lock()
		alertsLast = nil
		alertsMu.Unlock()
	}()

	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if strings.Contains(raw, `"alerts"`) || calls != 0 {
		t.Fatalf("before the first refresh: no key, and no fetch on the beat (calls=%d)", calls)
	}
	refreshAlerts(context.Background()) // what the background loop does once a minute
	if calls != 1 {
		t.Fatalf("one fetch per refresh, got %d", calls)
	}

	raw = buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	_ = buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if calls != 1 {
		t.Fatalf("a beat must SERVE the last value, never fetch: %d fetches", calls)
	}
	var body struct {
		Alerts map[string]any `json:"alerts"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"firing", "critical", "warning", "since", "at", "fingerprints"} {
		if _, ok := body.Alerts[k]; !ok {
			t.Fatalf("the contract key %q is missing: %v", k, body.Alerts)
		}
	}
	if len(body.Alerts) != 6 {
		t.Fatalf("the contract is exactly six keys; extras break the host side: %v", body.Alerts)
	}
	if body.Alerts["firing"].(float64) != 3 || body.Alerts["critical"].(float64) != 1 ||
		body.Alerts["warning"].(float64) != 1 {
		t.Fatalf("%v", body.Alerts)
	}
	if body.Alerts["since"].(string) != "2026-09-14T08:12:16Z" {
		t.Fatalf("since: %v", body.Alerts["since"])
	}
	if _, err := time.Parse(time.RFC3339, body.Alerts["at"].(string)); err != nil {
		t.Fatalf("at must be RFC3339: %v", body.Alerts["at"])
	}
	fps := body.Alerts["fingerprints"].([]any)
	if len(fps) != 3 || fps[0].(string) != "bbb2" {
		t.Fatalf("critical first: %v", fps)
	}

	// A refresh that FAILS keeps the last good value rather than publishing an
	// all-clear the box cannot stand behind.
	before := *alertsPayload()
	origGet := observeHTTPGet
	observeHTTPGet = func(context.Context, string) ([]byte, int, error) {
		return nil, 0, errors.New("connection refused")
	}
	refreshAlerts(context.Background())
	observeHTTPGet = origGet
	after := alertsPayload()
	if after == nil || after.At != before.At || after.Firing != before.Firing {
		t.Fatalf("a failed refresh must not overwrite the last good summary: %+v -> %+v", before, after)
	}
}

// mustSelector is the selector the op would actually build for a name on this
// box, so a test never hardcodes a string the product no longer produces.
func mustSelector(t *testing.T, name string) string {
	t.Helper()
	s, _, ok := observeLogSelector(name)
	if !ok {
		t.Fatalf("no selector for %q", name)
	}
	return s
}

// ── the wall at the socket: redirects and the dial control ───────────────────

// THE BLOCKING ONE. A configured Alertmanager answering 302 must not walk the
// box to the redirect target. Go follows up to ten redirects by default and the
// endpoints-file check only ever saw the CONFIGURED address, so this is the
// path by which an unattended 60 s loop would have made outbound GETs from
// inside the perimeter with the box's own identity.
func TestObserveNeverFollowsARedirect(t *testing.T) {
	reached := make(chan string, 8)
	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- r.URL.RequestURI()
		_, _ = w.Write([]byte(`[]`))
	}))
	defer off.Close()

	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, off.URL+"/api/v2/alerts?active=true", code)
			})
			out, errOut, exit := driveObserve(t, "observe:alerts", nil)
			select {
			case got := <-reached:
				t.Fatalf("THE WALL IS OPEN: the redirect target was fetched (%q). "+
					"out=%s", got, out)
			default:
			}
			// The 30x is a RESULT and is reported as the failure it is.
			if exit == 0 {
				t.Fatalf("a %d must be reported as a failure, not answered: %s", code, out)
			}
			if !strings.Contains(errOut, "HTTP "+strconv.Itoa(code)) {
				t.Fatalf("the refusal must name the status: %q", errOut)
			}
		})
	}

	// And the background refresh — the unattended path — publishes nothing
	// rather than following it.
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, off.URL+"/api/v2/alerts", http.StatusFound)
	})
	alertsMu.Lock()
	alertsLast = nil
	alertsMu.Unlock()
	defer func() {
		alertsMu.Lock()
		alertsLast = nil
		alertsMu.Unlock()
	}()
	refreshAlerts(context.Background())
	select {
	case got := <-reached:
		t.Fatalf("the 60 s refresh loop followed a redirect to %q", got)
	default:
	}
	if alertsPayload() != nil {
		t.Fatal("a redirected refresh must publish nothing")
	}
}

// The socket-level wall, which is what closes the rebinding shape: whatever the
// resolver says at connect time, a public address is refused before connect.
func TestObserveDialControlRefusesPublicAtConnectTime(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:443", "203.0.113.10:80", "[2606:4700::1111]:443"} {
		if err := observeDialControl("tcp", addr, nil); err == nil {
			t.Errorf("%s was allowed at the socket — rebinding is open", addr)
		} else if !strings.Contains(err.Error(), errObserveDialPublic) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	// The box's own neighbourhood still connects — the inverse, at the socket.
	for _, addr := range []string{"127.0.0.1:9093", "10.99.1.1:9093", "[fd00:1::10]:3100",
		"169.254.1.1:80", "100.64.0.1:3100"} {
		if err := observeDialControl("tcp", addr, nil); err != nil {
			t.Errorf("%s must be allowed: %v", addr, err)
		}
	}
	// A name that reached the dialer unresolved is refused rather than dialed.
	if err := observeDialControl("tcp", "evil.example:80", nil); err == nil {
		t.Error("an unresolved host at connect time must be refused")
	}

	// End to end through the real client: nothing leaves the box, because the
	// refusal happens before connect.
	_, _, err := observeHTTPGet(context.Background(), "http://8.8.8.8:80/api/v2/alerts")
	if err == nil || !strings.Contains(err.Error(), errObserveDialPublic) {
		t.Fatalf("the transport must carry the dial control: %v", err)
	}
}

// The body cap is implemented AND exercised: removing the LimitReader must
// fail a test, which it did not before.
func TestObserveBodyCapIsEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("z", 64*1024)
		for i := 0; i < 64; i++ { // 4 MiB, four times the cap
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	// An OVERSIZED body is an error that SAYS so. Handing back a clean 1 MiB of
	// cut bytes surfaced three frames later as "unexpected end of JSON input",
	// which blames the endpoint for something the reader did.
	if _, _, err := observeHTTPGet(context.Background(), srv.URL); err == nil {
		t.Fatal("a body past the cap must be an error, not a quiet truncation")
	} else if !strings.Contains(err.Error(), "response too large") {
		t.Fatalf("the error must name the reason: %v", err)
	}

	// A body at EXACTLY the cap is fine and comes back whole. That boundary is
	// the case a cap-sized read could not distinguish from a cut one at all,
	// which is why the read is cap+1.
	exact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("z", observeBodyCap)))
	}))
	defer exact.Close()
	body, code, err := observeHTTPGet(context.Background(), exact.URL)
	if err != nil {
		t.Fatalf("exactly at the cap must succeed: %v", err)
	}
	if code != 200 || len(body) != observeBodyCap {
		t.Fatalf("code=%d len=%d", code, len(body))
	}

	// End to end: the op refuses naming the size, never a parser error.
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("z", 64*1024)
		for i := 0; i < 32; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})
	_, errOut, exit := driveObserve(t, "observe:alerts", nil)
	if exit == 0 || !strings.Contains(errOut, "response too large") {
		t.Fatalf("exit=%d err=%q", exit, errOut)
	}
	if strings.Contains(errOut, "unexpected end of JSON") {
		t.Fatalf("a size problem must not surface as a parser error: %q", errOut)
	}
}

// ── silenced and inhibited alerts never page ─────────────────────────────────

// In Alertmanager v2 active/silenced/inhibited/unprocessed each default TRUE,
// so `?active=true` alone narrows nothing. Both halves are checked: the query
// string asks for the narrowing, and the box's own arithmetic refuses to count
// a non-active alert that arrives anyway.
func TestObserveAlertsExcludesSilencedAndInhibited(t *testing.T) {
	const mixed = `[
	 {"fingerprint":"act1","labels":{"alertname":"Real","severity":"critical"},
	  "startsAt":"2026-09-15T01:00:00Z","status":{"state":"active"}},
	 {"fingerprint":"sil2","labels":{"alertname":"Silenced","severity":"critical"},
	  "startsAt":"2026-09-10T01:00:00Z","status":{"state":"suppressed","silencedBy":["abc"]}},
	 {"fingerprint":"inh3","labels":{"alertname":"Inhibited","severity":"warning"},
	  "startsAt":"2026-09-11T01:00:00Z","status":{"state":"suppressed","inhibitedBy":["def"]}}
	]`
	var asked string
	fakeMonitoring(t, func(w http.ResponseWriter, r *http.Request) {
		asked = r.URL.RawQuery
		_, _ = w.Write([]byte(mixed))
	})
	if _, errOut, code := driveObserve(t, "observe:alerts", nil); code != 0 {
		t.Fatalf("exit %d %s", code, errOut)
	}
	for _, want := range []string{"active=true", "silenced=false", "inhibited=false"} {
		if !strings.Contains(asked, want) {
			t.Fatalf("the query must ask for %q — active=true alone narrows nothing: %q", want, asked)
		}
	}

	// The second half: a suppressed alert that arrives anyway is not firing.
	rep, err := parseAlerts([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	s := summarizeAlerts(rep, time.Now())
	if s.Firing != 1 || s.Critical != 1 || s.Warning != 0 {
		t.Fatalf("a silence is an operator saying stop telling me; only the active alert fires: %+v", s)
	}
	if len(s.Fingerprints) != 1 || s.Fingerprints[0] != "act1" {
		t.Fatalf("fingerprints: %v", s.Fingerprints)
	}
	// `since` is the oldest ACTIVE start — never the older silenced one.
	if s.Since == nil || *s.Since != "2026-09-15T01:00:00Z" {
		t.Fatalf("since must ignore suppressed alerts: %v", s.Since)
	}
}

// ── the refresh runs under the lifecycle context ─────────────────────────────

func TestAlertsRefreshHonoursTheLifecycleContext(t *testing.T) {
	entered := make(chan struct{})
	orig := observeHTTPGet
	observeHTTPGet = func(ctx context.Context, _ string) ([]byte, int, error) {
		close(entered)
		<-ctx.Done() // a server that accepts and never answers
		return nil, 0, ctx.Err()
	}
	defer func() { observeHTTPGet = orig }()
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { refreshAlerts(ctx); close(done) }()
	<-entered
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// The 20 s op budget would outlive a shutdown if the fetch were rooted
		// at context.Background() instead of the heartbeat's own context.
		t.Fatal("cancelling the lifecycle context must end an in-flight fetch")
	}
	if alertsPayload() != nil {
		t.Fatal("a cancelled refresh must publish nothing")
	}
}

// ── scope: this box, and saying so when it cannot be ─────────────────────────

// The three journal names are pinned to THIS box; k8s-system cannot be, because
// pod streams carry no `node` label at all — every kube-system stream is
// {cluster,container,instance,job,namespace,pod,service_name}, and
// {namespace="kube-system",node="example-host"} returns zero lines. The
// report states which, so nobody infers scope from the name.
func TestObserveLogsScopedToThisBox(t *testing.T) {
	orig := observeHostname
	observeHostname = func() (string, error) { return "example-host", nil }
	defer func() { observeHostname = orig }()

	for _, name := range []string{"kernel", "sshd", "bastion"} {
		sel, scope, ok := observeLogSelector(name)
		if !ok {
			t.Fatalf("%s: no selector", name)
		}
		if !strings.Contains(sel, `node="example-host"`) {
			t.Fatalf("%s must be scoped to this box, got %q", name, sel)
		}
		if scope != observeScopeNode {
			t.Fatalf("%s scope %q", name, scope)
		}
	}
	// The one that cannot be scoped says cluster, and carries no node matcher
	// — a matcher on a label that does not exist returns nothing at all.
	sel, scope, _ := observeLogSelector("k8s-system")
	if strings.Contains(sel, "node=") || scope != observeScopeCluster {
		t.Fatalf("k8s-system: %q %q", sel, scope)
	}
	// The bastion's own unit, by the name install.sh writes.
	if s, _, _ := observeLogSelector("bastion"); !strings.Contains(s, `unit="privatae-bastion.service"`) {
		t.Fatalf("bastion selector: %q", s)
	}

	// A box that cannot read its hostname answers cluster-wide and SAYS so,
	// rather than silently presenting the estate as this machine.
	observeHostname = func() (string, error) { return "", errors.New("no hostname") }
	sel, scope, _ = observeLogSelector("sshd")
	if strings.Contains(sel, "node=") {
		t.Fatalf("no hostname must mean no node matcher: %q", sel)
	}
	if scope != observeScopeCluster {
		t.Fatalf("an unscoped answer must not claim node scope: %q", scope)
	}
}

// An empty answer is the most misreadable one this op gives. Measured on a
// real box: the bastion's own service can run for hours writing zero journal
// lines, so this is the normal case, not an edge.
func TestObserveLogsEmptyResultSaysSo(t *testing.T) {
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	})
	for _, name := range logNames() {
		out, errOut, code := driveObserve(t, "observe:logs", []string{name, "30"})
		if code != 0 {
			t.Fatalf("%s: exit %d %s", name, code, errOut)
		}
		var rep logsReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatal(err)
		}
		if rep.Lines != 0 || rep.Log != "" {
			t.Fatalf("%s: %+v", name, rep)
		}
		if rep.Note == "" {
			t.Fatalf("%s: an empty body reads as 'nothing happened'; it must say "+
				"which selector came back with nothing", name)
		}
		if !strings.Contains(rep.Note, rep.Selector) || !strings.Contains(rep.Note, "30 minutes") {
			t.Fatalf("%s: the note must name the selector and the window: %q", name, rep.Note)
		}
		if rep.Scope == "" {
			t.Fatalf("%s: every answer states its scope", name)
		}
	}
	// A non-empty answer carries no note — the note is the absence marker, not
	// a decoration on every reply.
	fakeMonitoring(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[
		 {"stream":{},"values":[["100","a line"]]}]}}`))
	})
	out, _, _ := driveObserve(t, "observe:logs", []string{"sshd"})
	var rep logsReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Note != "" {
		t.Fatalf("a non-empty answer must carry no note: %q", rep.Note)
	}
}

// ── the counts must be TRUE even when the rows are capped ────────────────────

// `firing` used to saturate at the row cap, because the cap was applied to the
// raw list before anything looked at it. An estate with 400 alerts firing then
// produced the same beat as one with 200 — the number a human reads as severity,
// stuck at a constant.
func TestAlertCountsAreNotCappedWithTheRows(t *testing.T) {
	const n = 250
	var rows []string
	for i := 0; i < n; i++ {
		sev := "warning"
		if i%5 == 0 {
			sev = "critical"
		}
		rows = append(rows, fmt.Sprintf(
			`{"fingerprint":"fp%03d","labels":{"alertname":"A%03d","severity":%q},`+
				`"startsAt":"2026-09-15T01:00:00Z","status":{"state":"active"}}`, i, i, sev))
	}
	rep, err := parseAlerts([]byte("[" + strings.Join(rows, ",") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ActiveTotal != n {
		t.Fatalf("active_total must be the real number: %d", rep.ActiveTotal)
	}
	if rep.Count != observeAlertCap || len(rep.Alerts) != observeAlertCap {
		t.Fatalf("the ROWS are capped at %d: count=%d rows=%d", observeAlertCap, rep.Count, len(rep.Alerts))
	}
	if !rep.Truncated {
		t.Fatal("a row cut must be reported")
	}

	s := summarizeAlerts(rep, time.Now())
	if s.Firing != n {
		t.Fatalf("firing must count every active alert, not the capped rows: %d (want %d)", s.Firing, n)
	}
	if s.Critical != 50 || s.Warning != 200 {
		t.Fatalf("the severity counts come from the full set too: %+v", s)
	}
	if len(s.Fingerprints) != alertsFingerprintCap {
		t.Fatalf("only the fingerprint LIST is capped: %d", len(s.Fingerprints))
	}
	// The contract stays exactly six keys — the counts got truer, not wider.
	b, _ := json.Marshal(s)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 6 {
		t.Fatalf("the six-key contract must not change: %v", m)
	}
}

// The state filter runs BEFORE the cap, so 200 silenced alerts cannot crowd the
// active ones out of the rows.
func TestTheStateFilterRunsBeforeTheRowCap(t *testing.T) {
	var rows []string
	for i := 0; i < observeAlertCap; i++ {
		rows = append(rows, fmt.Sprintf(
			`{"fingerprint":"sil%03d","labels":{"alertname":"S","severity":"critical"},`+
				`"startsAt":"2026-09-10T01:00:00Z","status":{"state":"suppressed"}}`, i))
	}
	rows = append(rows, `{"fingerprint":"real","labels":{"alertname":"Real","severity":"critical"},`+
		`"startsAt":"2026-09-15T01:00:00Z","status":{"state":"active"}}`)
	rep, err := parseAlerts([]byte("[" + strings.Join(rows, ",") + "]"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ActiveTotal != 1 || rep.Count != 1 {
		t.Fatalf("200 silences must not push the one real alert out of the answer: %+v", rep.Count)
	}
	if rep.Alerts[0].Fingerprint != "real" {
		t.Fatalf("%+v", rep.Alerts[0])
	}
	if s := summarizeAlerts(rep, time.Now()); s.Firing != 1 || s.Critical != 1 {
		t.Fatalf("%+v", s)
	}
}

// ── removing the alertmanager key stops the beat claiming to watch ───────────

// A transient failure keeps the last good value; UNCONFIGURED clears it. Getting
// that backwards froze a summary onto every beat until the process restarted.
func TestUnconfiguredClearsTheCachedSummaryButAFailureDoesNot(t *testing.T) {
	alertsMu.Lock()
	alertsLast = nil
	alertsMu.Unlock()
	defer func() {
		alertsMu.Lock()
		alertsLast = nil
		alertsMu.Unlock()
	}()

	restore := func() func() {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(fxAlerts))
		}))
		t.Cleanup(srv.Close)
		return withEndpointsFile(t, fmt.Sprintf(`{"alertmanager":%q}`, srv.URL))
	}()
	refreshAlerts(context.Background())
	if alertsPayload() == nil {
		t.Fatal("configured and reachable: there must be a summary")
	}

	// A transient failure — the Alertmanager is named but unreachable. The
	// alerts are still firing; this box just cannot see them this minute.
	origGet := observeHTTPGet
	observeHTTPGet = func(context.Context, string) ([]byte, int, error) {
		return nil, 0, errors.New("connection refused")
	}
	refreshAlerts(context.Background())
	observeHTTPGet = origGet
	if alertsPayload() == nil {
		t.Fatal("a transient failure must KEEP the last good summary")
	}

	// The admin removes the key. This box is no longer watching anything and
	// must stop saying otherwise.
	restore()
	defer withEndpointsFile(t, `{"loki":"http://127.0.0.1:3100"}`)()
	refreshAlerts(context.Background())
	if alertsPayload() != nil {
		t.Fatal("with the alertmanager key removed the summary must be CLEARED, " +
			"not frozen onto every beat until restart")
	}
	raw := buildHeartbeatBody("", "box", "linux", "test", "pub", "fp", "", "", false, nil, nil, nil)
	if strings.Contains(raw, `"alerts"`) {
		t.Fatalf("and the key must be absent from the beat again: %s", raw)
	}

	// The file going away entirely is the same story.
	refreshAlerts(context.Background())
	defer withNoEndpointsFile(t)()
	refreshAlerts(context.Background())
	if alertsPayload() != nil {
		t.Fatal("no endpoints file at all must clear it too")
	}
}
