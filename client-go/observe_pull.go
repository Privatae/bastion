package main

// observe:alerts / observe:metrics / observe:logs — the PULL half of the
// observe family.
//
// Three read-only ops that read the monitoring services sitting beside this
// box: an Alertmanager, a Prometheus, a Loki, each named in
// observe-endpoints.json by the admin at install (observe_endpoints.go). They
// are HTTP, so the exec seam is not used at all and there is no Linux driver:
// the pattern is observe:net, which execs nothing either.
//
// The discipline the rest of the family keeps with a fixed argv, these keep
// with a fixed TABLE. The host never sends PromQL, never sends LogQL, and never
// sends a URL. Its argument is a NAME; the box owns the query that name maps
// to. An unknown name is refused with the known names listed, so the host can
// see the whole surface without guessing at it.
//
// Cross-platform, no build tag: nothing here touches /proc, systemd or nft, so
// observe_ops_other.go has nothing to stub. These three answer the same on
// Linux, macOS and Windows — which is the point on a customer's bastion, where
// the box next to their Alertmanager may not be the box we would have picked.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// observeBodyCap bounds ONE response body. Measured against a real estate:
// a few dozen active Alertmanager alerts came to 41 KB of v2 JSON and the
// largest of the six instant vectors (`up`, 29 series) was 8 KB. 1 MiB is room
// for an estate a couple of orders of magnitude larger without letting a job
// body grow without bound.
const observeBodyCap = 1 << 20

// errObserveDialPublic is the socket-level refusal. A named constant so a test
// pins the REASON and not merely the failure.
const errObserveDialPublic = "is a public address — refused at the socket"

// observeDialControl is the LAST wall, and the only one that cannot be raced.
//
// Validating the endpoints file proves what the admin WROTE was private. It
// cannot prove what the box will CONNECT to, and two things open that gap:
//
//   - A REDIRECT. Nothing in the file's URL constrains where a 30x points, so a
//     compromised or merely misconfigured Alertmanager could hand the box a
//     Location anywhere. That is closed in observeHTTPClient by never following
//     one; this is the backstop if that ever changes.
//   - DNS. A hostname endpoint is resolved once by validateObserveEndpoint and
//     again by the transport, and between those two resolutions the answer can
//     change — the rebinding shape. Re-resolving more carefully cannot close
//     that, because there is always a LAST resolution and the check has to come
//     after it.
//
// net.Dialer.Control runs on the ADDRESS THE SOCKET IS ABOUT TO CONNECT TO,
// after resolution and before connect, so no window is left. Every path to the
// network in this file goes through it. It is the socket-level statement of the
// rule the file header sets out: this family reads the box's own neighbourhood
// and may never be turned into a way to make the box fetch the internet.
var observeDialControl = func(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("refused: unreadable socket address " + address)
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		// Control is handed a resolved literal. Anything else means the
		// resolution path changed underneath this, and the safe answer is no.
		return errors.New("refused: " + host + " is not an IP literal at connect time")
	}
	if !observeEndpointAllowed(a) {
		return errors.New("refused: " + a.Unmap().String() + " " + errObserveDialPublic)
	}
	return nil
}

// observeHTTPClient is the client all three ops use. Built per call because it
// is cheap — one connection, no keep-alives — and because a shared client would
// let one op's dead connection be handed to another.
func observeHTTPClient() *http.Client {
	return &http.Client{
		// A REDIRECT IS A RESULT, NEVER A HOP. Go follows up to ten by default,
		// and the endpoints-file wall checks only the address the ADMIN
		// configured — so a 302 from the configured Alertmanager would walk the
		// box straight out of its own neighbourhood, carrying the query string,
		// on the unattended 60 s refresh loop. ErrUseLastResponse hands the 30x
		// back as the response and observePull reports it as the non-2xx it is.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// DisableKeepAlives for the same reason probeNet sets it: one read,
			// then the connection is done.
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: netProbeTimeout,
				Control: observeDialControl,
			}).DialContext,
		},
	}
}

// observeHTTPGet is the ONE seam through which these three ops reach the
// network, the same way observeExec is the one seam for the exec ops. A
// variable so the tests can point it at an httptest server or record the URLs
// and prove no caller value ever reaches one.
var observeHTTPGet = func(ctx context.Context, rawURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	// The ctx carries the shared op budget, so a server that accepts and never
	// answers is cut at the same deadline every other op is cut at — the HTTP
	// analogue of the WaitDelay on the exec seam, where the transport rather
	// than a grandchild is what would otherwise hold the read open past the
	// kill.
	resp, err := observeHTTPClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	// LimitReader, never a bare ReadAll: an endpoint that streams for ever costs
	// one megabyte and the op budget, never the process.
	//
	// cap+1, not cap. Reading exactly the cap cannot tell a body that happens to
	// be 1 MiB from one that was CUT at 1 MiB, so an oversized response came back
	// as a clean 1 MiB of valid-looking bytes and surfaced three frames later as
	// "unexpected end of JSON input" — a parser error blaming the endpoint for
	// something this function did. One extra byte makes the overflow decidable
	// here, where it can be named.
	body, err := io.ReadAll(io.LimitReader(resp.Body, observeBodyCap+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > observeBodyCap {
		return nil, resp.StatusCode, errors.New("response too large (> 1 MiB)")
	}
	return body, resp.StatusCode, nil
}

// opBudgetFrom is opBudget (observe_ops.go:74) with a PARENT. The background
// alerts refresh runs under the heartbeat goroutine's lifecycle context, so a
// shutdown cancels an in-flight fetch instead of leaving it to run out its own
// 20 s against a box that is going away.
func opBudgetFrom(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, observeOpBudget)
}

// observePull does the shared work of all three ops: resolve the endpoint,
// fetch, check the status, hand back the body. The unconfigured string is the
// observe:k8s answer — reported, exit 0 — and err is a refusal.
func observePull(ctx context.Context, key, path string) (body []byte, unconfigured string, err error) {
	base, unconfigured, err := observeEndpointFor(ctx, key)
	if unconfigured != "" || err != nil {
		return nil, unconfigured, err
	}
	raw, code, err := observeHTTPGet(ctx, base+path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", errors.New(key + ": timeout")
		}
		return nil, "", errors.New(key + ": " + err.Error())
	}
	if code < 200 || code > 299 {
		return nil, "", errors.New(key + ": HTTP " + strconv.Itoa(code))
	}
	return raw, "", nil
}

// writeObservePull is the one answer path for the three ops: an unconfigured
// box reports the observe:k8s shape at exit 0, a refusal says why at exit 2.
func writeObservePull(ws *websocket.Conn, unconfigured string, err error, v any) {
	if err != nil {
		sendMgmt(ws, 'R', []byte("refused: "+err.Error()+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	if unconfigured != "" {
		writeObserve(ws, map[string]any{"supported": false, "reason": unconfigured})
		return
	}
	writeObserve(ws, v)
}

// ── observe:alerts ───────────────────────────────────────────────────────────

// alertmanagerAlertsPath is Alertmanager's v2 API.
//
// ALL FOUR FILTER FLAGS ARE NAMED, not just active. In v2 each of active,
// silenced, inhibited and unprocessed defaults to TRUE, so `?active=true` alone
// narrows nothing — it re-states one default and leaves the other three on. An
// alert somebody deliberately silenced would then ride the heartbeat as firing,
// which is the one thing a silence exists to prevent.
//
// Measured against a real Alertmanager: `?active=true` returned the same
// count as the bare `/api/v2/alerts`, confirming the flag was doing nothing;
// `?active=false&silenced=true&inhibited=true` returned 0 against that same
// instance, so the bug could not be shown live there. It is closed here and
// proven by fixture instead (TestObserveAlertsExcludesSilencedAndInhibited).
const alertmanagerAlertsPath = "/api/v2/alerts?active=true&silenced=false&inhibited=false&unprocessed=false"

// observeAlertCap and observeLabelValueCap bound one answer. Measured against
// a real estate: a few dozen active alerts, so 200 is an order of magnitude
// of headroom — re-measure before lowering it. The cut is reported rather
// than hidden. 512 bytes is past every label an ordinary estate sets and
// short of an annotation-sized value pasted into one.
const (
	observeAlertCap      = 200
	observeLabelValueCap = 512
)

// amAlert is the slice of Alertmanager's v2 alert this box reads. Annotations
// are deliberately not carried: they are prose written for a human reading
// Grafana, they are the largest field on the wire, and nothing in the host's
// lane keys on them.
type amAlert struct {
	Fingerprint string            `json:"fingerprint"`
	Labels      map[string]string `json:"labels"`
	StartsAt    string            `json:"startsAt"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
}

type observedAlert struct {
	Fingerprint string            `json:"fingerprint"`
	Alertname   string            `json:"alertname"`
	Severity    string            `json:"severity"`
	State       string            `json:"state"`
	StartsAt    string            `json:"starts_at"`
	Labels      map[string]string `json:"labels"`
	// The labels whose VALUE was over observeLabelValueCap and was therefore
	// dropped. Named rather than silently missing: a host that sees no
	// `description` label cannot otherwise tell "not set" from "too big".
	DroppedLabels []string `json:"dropped_labels,omitempty"`
}

type alertsReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source"`
	// Count is how many rows are in Alerts — always len(Alerts), so a reader
	// never has to reconcile the two. ActiveTotal is how many there ACTUALLY
	// are; the two differ exactly when Truncated is set, which is what makes a
	// truncation actionable rather than merely admitted.
	Count       int             `json:"count"`
	ActiveTotal int             `json:"active_total"`
	Alerts      []observedAlert `json:"alerts"`
	Truncated   bool            `json:"truncated,omitempty"`

	// all is every ACTIVE alert, uncapped, and is deliberately not serialized —
	// it exists so the heartbeat's counts can be true while the wire stays
	// bounded. See summarizeAlerts.
	all []observedAlert
}

// parseAlerts reduces an Alertmanager v2 body to the typed set.
//
// ORDER MATTERS HERE, and getting it wrong was a real bug: the row cap used to
// be applied to the RAW list, before the state filter, so 250 alerts were cut to
// 200 and only then examined. Everything downstream — including the heartbeat's
// `firing` — therefore saturated silently at 200 and an estate with 400 alerts
// firing looked exactly like one with 200. Filter first, then count, then cap.
//
// Suppressed alerts are dropped from the ROWS too, not just the counts. The
// request already asks for active only (alertmanagerAlertsPath); a silenced
// alert that arrives anyway is one this box was told not to report, and
// returning it as a row while excluding it from every count would be the worst
// of both.
func parseAlerts(raw []byte) (alertsReport, error) {
	var list []amAlert
	if err := json.Unmarshal(raw, &list); err != nil {
		return alertsReport{}, err
	}
	rep := alertsReport{Supported: true, Source: observeKeyAlertmanager, Alerts: []observedAlert{}}
	for _, a := range list {
		// The state filter, BEFORE the cap. An empty state is treated as active:
		// an Alertmanager that did not say is not evidence of a silence.
		if a.Status.State != "" && a.Status.State != "active" {
			continue
		}
		o := observedAlert{Fingerprint: a.Fingerprint, State: a.Status.State, StartsAt: a.StartsAt,
			Labels: map[string]string{}}
		for k, v := range a.Labels {
			if len(v) > observeLabelValueCap {
				o.DroppedLabels = append(o.DroppedLabels, k)
				rep.Truncated = true
				continue
			}
			o.Labels[k] = v
		}
		sort.Strings(o.DroppedLabels)
		o.Alertname = o.Labels["alertname"]
		o.Severity = o.Labels["severity"]
		rep.all = append(rep.all, o)
	}
	rep.ActiveTotal = len(rep.all)
	rep.Alerts = rep.all
	if len(rep.Alerts) > observeAlertCap {
		// The ROWS are capped; the counts above are not. Copied rather than
		// resliced so the wire slice cannot alias `all` and be mutated through it.
		rep.Alerts = append([]observedAlert(nil), rep.all[:observeAlertCap]...)
		rep.Truncated = true
	}
	if rep.Alerts == nil {
		rep.Alerts = []observedAlert{}
	}
	rep.Count = len(rep.Alerts)
	return rep, nil
}

// handleObserveAlerts takes no argument: the op is the whole active set, the
// way observe:host is the whole posture. Args are ignored exactly as they are
// there, so it stays out of the arg-taking ops (observeArgsRecorded,
// machinestore.go, lists them).
func handleObserveAlerts(ws *websocket.Conn, _ string, _ []string) {
	ctx, cancel := opBudget()
	defer cancel()
	raw, unconfigured, err := observePull(ctx, observeKeyAlertmanager, alertmanagerAlertsPath)
	if unconfigured != "" || err != nil {
		writeObservePull(ws, unconfigured, err, nil)
		return
	}
	rep, perr := parseAlerts(raw)
	if perr != nil {
		writeObservePull(ws, "", errors.New("alertmanager: "+perr.Error()), nil)
		return
	}
	writeObservePull(ws, "", nil, rep)
}

// ── observe:metrics ──────────────────────────────────────────────────────────

// observeMetricQueries is the whole PromQL surface of this box. The host sends
// a NAME; the box owns the query. Adding a question means shipping a bastion,
// which is the trade this table exists to make: no free query language reaches
// a production Prometheus through a pairing grant.
//
// The six are the ones the plan names (§2a): is anything scraping, and the four
// node/pod conditions a finding rule is written against.
var observeMetricQueries = map[string]string{
	"up":        `up`,
	"node_cpu":  `1 - avg by (instance)(rate(node_cpu_seconds_total{mode="idle"}[5m]))`,
	"node_mem":  `1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`,
	"node_disk": `1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay"}`,
	// increase() over 1h rather than a bare counter: the counter's VALUE is
	// lifetime restarts, which never goes down and so can never clear.
	"pod_restarts": `sum by (namespace,pod)(increase(kube_pod_container_status_restarts_total[1h])) > 0`,
	"pod_oom":      `sum by (namespace,pod)(kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}) > 0`,
}

// observeSeriesCap bounds one answer.
//
// Every one of the six, measured against a real Prometheus: `up` was the
// largest instant vector by a wide margin, the rest single digits or zero. So
// 500 is roughly an order of magnitude of headroom over the largest vector
// measured. Re-measure before lowering it: `up` grows with every scrape
// target added, and the cap is the one number here that would silently drop
// rows a finding rule is counting on.
const observeSeriesCap = 500

type observedSeries struct {
	Labels map[string]string `json:"labels"`
	Value  string            `json:"value"`
	TS     float64           `json:"ts"`
}

type metricsReport struct {
	Supported bool             `json:"supported"`
	Reason    string           `json:"reason,omitempty"`
	Source    string           `json:"source"`
	Name      string           `json:"name"`
	Query     string           `json:"query"`
	Count     int              `json:"count"`
	Series    []observedSeries `json:"series"`
	Truncated bool             `json:"truncated,omitempty"`
}

// metricNames lists the table, sorted, for the refusal message.
func metricNames() []string {
	names := make([]string, 0, len(observeMetricQueries))
	for k := range observeMetricQueries {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// parseInstantVector reduces a Prometheus /api/v1/query answer to the series
// list. A non-"success" status or a non-vector result is an error rather than
// an empty list: "no series" and "the query was rejected" must never read the
// same to a finding rule.
func parseInstantVector(raw []byte) ([]observedSeries, bool, error) {
	var res struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, false, err
	}
	if res.Status != "success" {
		if res.Error != "" {
			return nil, false, errors.New(res.Error)
		}
		return nil, false, errors.New("prometheus status " + res.Status)
	}
	if res.Data.ResultType != "vector" {
		return nil, false, errors.New("expected an instant vector, got " + res.Data.ResultType)
	}
	truncated := false
	rows := res.Data.Result
	if len(rows) > observeSeriesCap {
		rows = rows[:observeSeriesCap]
		truncated = true
	}
	out := make([]observedSeries, 0, len(rows))
	for _, r := range rows {
		s := observedSeries{Labels: r.Metric}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		// [ <unix_float>, "<value as string>" ] — Prometheus sends the sample
		// value as a STRING so NaN and Inf survive JSON; it is passed through
		// as one rather than parsed into a float that cannot hold them.
		if len(r.Value) == 2 {
			_ = json.Unmarshal(r.Value[0], &s.TS)
			_ = json.Unmarshal(r.Value[1], &s.Value)
		}
		out = append(out, s)
	}
	return out, truncated, nil
}

func handleObserveMetrics(ws *websocket.Conn, _ string, args []string) {
	if len(args) != 1 {
		sendMgmt(ws, 'R', []byte("observe:metrics takes exactly one argument: a metric name ("+
			strings.Join(metricNames(), ", ")+")\n"))
		sendMgmtExit(ws, 2)
		return
	}
	name := args[0]
	query, ok := observeMetricQueries[name]
	if !ok {
		sendMgmt(ws, 'R', []byte("refused: unknown metric name; this box answers only "+
			strings.Join(metricNames(), ", ")+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	ctx, cancel := opBudget()
	defer cancel()
	// The name is a table KEY, so what goes on the wire is the box's own PromQL
	// and never the caller's bytes. It is escaped anyway: the value being
	// encoded is a constant from this file, and an encoder round a constant is
	// what keeps it true if the table ever gains a query with a '&' in it.
	raw, unconfigured, err := observePull(ctx, observeKeyPrometheus,
		"/api/v1/query?query="+url.QueryEscape(query))
	if unconfigured != "" || err != nil {
		writeObservePull(ws, unconfigured, err, nil)
		return
	}
	series, truncated, perr := parseInstantVector(raw)
	if perr != nil {
		writeObservePull(ws, "", errors.New("prometheus: "+perr.Error()), nil)
		return
	}
	writeObservePull(ws, "", nil, metricsReport{Supported: true, Source: observeKeyPrometheus,
		Name: name, Query: query, Count: len(series), Series: series, Truncated: truncated})
}

// ── observe:logs ─────────────────────────────────────────────────────────────

// observeLogSelectors is the whole LogQL surface, keyed by name, for the same
// reason the PromQL table exists.
//
// The label vocabulary is NOT guessed: it is what the collector actually
// sets, read from its own configuration and then confirmed against a live
// Loki.
//
//   - The collector's journal relabel maps __journal__systemd_unit -> `unit`
//     and sets a job label identifying journal streams. So journal streams
//     carry that job label and a `unit`.
//   - There is NO unit called "kernel". The live label values for `unit` are
//     all .service/.scope unit names — because kernel and audit lines arrive
//     over the kernel transport and have no __journal__systemd_unit at all, so
//     the relabel leaves `unit` empty. The honest selector for them is
//     therefore the journal with an EMPTY unit, confirmed live: an empty-unit
//     journal selector returns the kernel/apparmor/audit lines.
//   - The journal relabel also maps __journal__hostname -> `node`, and the
//     live `node` label values are exactly the node hostnames. That is what
//     scopes the three journal selectors to THIS box — see
//     observeLogSelector.
//   - Pod logs come from the collector's Kubernetes source. Its config
//     DECLARES a node relabel for them, but it does not survive: measured
//     live, every kube-system stream carries {cluster, container, instance,
//     job, namespace, pod, service_name} and NO `node` at all, and scoping a
//     kube-system query to one node's hostname returns zero lines while the
//     unscoped query returns plenty. So k8s-system CANNOT be scoped to this
//     box and is cluster-wide; the report says which it is, rather than
//     letting a reader assume the scope from the op's name.
//
// SCOPE. The stated purpose of this family is the box's own neighbourhood, and
// an unscoped journal selector is not that — sshd unscoped returned four nodes'
// streams. The three journal names are therefore pinned to this box's hostname
// by default. There is no `all` variant: a host that wants another box's logs
// asks that box, which is the whole shape of the bastion lane.
var observeLogSelectorTemplates = map[string]string{
	"kernel":     `{job="systemd-journal", unit=""%s}`,
	"sshd":       `{job="systemd-journal", unit="ssh.service"%s}`,
	"bastion":    `{job="systemd-journal", unit="privatae-bastion.service"%s}`,
	"k8s-system": `{namespace="kube-system"}`,
}

// observeLogScope is the value the `scope` field carries, so the host never has
// to infer from the op's name how wide the answer was.
const (
	observeScopeNode    = "node"    // this box only
	observeScopeCluster = "cluster" // every node shipping to this Loki
)

// observeHostname is the resolver seam for the node scope (a var so a test can
// pin it). os.Hostname is what the journal's __journal__hostname is, by
// definition of the journal.
var observeHostname = os.Hostname

// observeLogSelector builds the selector for a name, scoped to this box where
// the label exists to do it with. A box whose hostname cannot be read falls
// back to the unscoped journal rather than answering nothing — and SAYS so
// through the returned scope, because a cluster-wide answer presented as this
// box's own is the failure this whole field exists to prevent.
func observeLogSelector(name string) (selector, scope string, ok bool) {
	tmpl, ok := observeLogSelectorTemplates[name]
	if !ok {
		return "", "", false
	}
	if !strings.Contains(tmpl, "%s") {
		return tmpl, observeScopeCluster, true
	}
	host, err := observeHostname()
	if err != nil || host == "" {
		return fmt.Sprintf(tmpl, ""), observeScopeCluster, true
	}
	return fmt.Sprintf(tmpl, `, node=`+strconv.Quote(host)), observeScopeNode, true
}

const (
	observeLogMinutesDefault = 15
	observeLogMinutesMax     = 60
	// observeLogLineLimit is what Loki is ASKED for. The byte cap below is what
	// actually bounds the answer; this keeps the server from building a far
	// larger page than 200 KB could ever carry.
	observeLogLineLimit = 5000
)

type logsReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source"`
	Name      string `json:"name"`
	Selector  string `json:"selector"`
	// Scope is "node" (this box) or "cluster" (every node shipping to this
	// Loki). Stated rather than implied: three of the four names are scoped to
	// this box and k8s-system cannot be, and a reader must not have to infer
	// which from the op's name.
	Scope     string `json:"scope"`
	Minutes   int    `json:"minutes"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	// Note is set when the answer is EMPTY. "Nothing was logged" and "nothing
	// came back" look identical in an empty body, and the difference is the
	// whole question an operator is asking. Measured on a real box: the
	// bastion's own unit (deploy/install.sh) can go many hours writing zero
	// journal lines, so an empty `bastion` answer is the honest and expected
	// one, and it has to say so instead of reading as a broken selector.
	Note string `json:"note,omitempty"`
	Log  string `json:"log"`
}

func logNames() []string {
	names := make([]string, 0, len(observeLogSelectorTemplates))
	for k := range observeLogSelectorTemplates {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

type lokiLine struct {
	ns   int64
	text string
}

// parseLokiStreams flattens a query_range answer into one time-ordered list,
// OLDEST FIRST — Loki is asked backward so the newest lines are the ones that
// survive a server-side limit, and they are reversed here so a reader ends on
// the most recent line, the way `dmesg -T` does.
func parseLokiStreams(raw []byte) ([]lokiLine, error) {
	var res struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	if res.Status != "success" {
		return nil, errors.New("loki status " + res.Status)
	}
	var out []lokiLine
	for _, st := range res.Data.Result {
		for _, v := range st.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, lokiLine{ns: ns, text: v[1]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ns < out[j].ns })
	return out, nil
}

// parseLogMinutes reads the optional second argument. Out of range is REFUSED
// rather than clamped: a host that asked for 600 minutes and silently got 60
// would draw a conclusion about ten hours from a quarter of one.
func parseLogMinutes(args []string) (int, error) {
	if len(args) < 2 {
		return observeLogMinutesDefault, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(args[1]))
	if err != nil {
		return 0, errors.New("minutes must be a whole number")
	}
	if n < 1 || n > observeLogMinutesMax {
		return 0, errors.New("minutes must be between 1 and " + strconv.Itoa(observeLogMinutesMax))
	}
	return n, nil
}

func handleObserveLogs(ws *websocket.Conn, _ string, args []string) {
	if len(args) < 1 || len(args) > 2 {
		sendMgmt(ws, 'R', []byte("observe:logs takes a name ("+strings.Join(logNames(), ", ")+
			") and optionally minutes (1-"+strconv.Itoa(observeLogMinutesMax)+")\n"))
		sendMgmtExit(ws, 2)
		return
	}
	name := args[0]
	selector, scope, ok := observeLogSelector(name)
	if !ok {
		sendMgmt(ws, 'R', []byte("refused: unknown log name; this box answers only "+
			strings.Join(logNames(), ", ")+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	minutes, err := parseLogMinutes(args)
	if err != nil {
		sendMgmt(ws, 'R', []byte("refused: "+err.Error()+"\n"))
		sendMgmtExit(ws, 2)
		return
	}
	ctx, cancel := opBudget()
	defer cancel()
	now := time.Now()
	q := url.Values{}
	q.Set("query", selector)
	q.Set("start", strconv.FormatInt(now.Add(-time.Duration(minutes)*time.Minute).UnixNano(), 10))
	q.Set("end", strconv.FormatInt(now.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(observeLogLineLimit))
	q.Set("direction", "backward")
	raw, unconfigured, err := observePull(ctx, observeKeyLoki, "/loki/api/v1/query_range?"+q.Encode())
	if unconfigured != "" || err != nil {
		writeObservePull(ws, unconfigured, err, nil)
		return
	}
	lines, perr := parseLokiStreams(raw)
	if perr != nil {
		writeObservePull(ws, "", errors.New("loki: "+perr.Error()), nil)
		return
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(time.Unix(0, l.ns).UTC().Format(time.RFC3339))
		b.WriteString(" ")
		b.WriteString(l.text)
		b.WriteString("\n")
	}
	// capLines keeps the LAST lines and the LAST bytes (observe_ops.go:933), so
	// a cut drops the OLDEST — which is the right end to lose when the answer
	// is ordered newest last. Same 200 KB cap `ufw status verbose` is held to.
	text, cut := capLines(b.String(), observeLogLineLimit, observeTextCap)
	n := 0
	if strings.TrimSpace(text) != "" {
		n = len(strings.Split(strings.TrimRight(text, "\n"), "\n"))
	}
	rep := logsReport{Supported: true, Source: observeKeyLoki, Name: name, Selector: selector,
		Scope: scope, Minutes: minutes, Lines: n, Truncated: cut, Log: text}
	if n == 0 {
		// An empty body is the most misreadable answer this op can give: it
		// looks exactly like "nothing happened" when it may equally be "that
		// selector matches nothing on this box". Say which query, over which
		// window, came back with nothing, and let the reader judge.
		rep.Note = "no lines from " + selector + " in the last " +
			strconv.Itoa(minutes) + " minutes"
	}
	writeObservePull(ws, "", nil, rep)
}

// ── the heartbeat's alerts summary ───────────────────────────────────────────
//
// THE CONTRACT, which the host side is being built against:
//
//	"alerts": {"firing": n, "critical": n, "warning": n,
//	           "since": "<RFC3339 of the oldest active startsAt>" | null,
//	           "at": "<RFC3339 of this refresh>",
//	           "fingerprints": ["...", ...]}   // at most 20, critical first
//
// The key is ABSENT — not zeroed — when no endpoints file names an
// alertmanager. That is the same nil-vs-empty rule peers and pairings keep in
// agents.go (the note at agents.go:622-631): absence means "this box did not
// look", an empty/zero summary means "this box looked and there is nothing".
// A zero `firing` from a box with no Alertmanager would read as an all-clear
// from a machine nobody is watching, which is the worse of the two lies.
//
// A refresh that FAILS keeps the last good value rather than publishing zeros,
// for the same reason; its `at` stops moving, which is how the host sees the
// summary has gone stale. Before the first successful refresh there is no key
// at all — the way posture is absent until its first pass (observe_ops.go:795).

type alertsSummary struct {
	Firing       int      `json:"firing"`
	Critical     int      `json:"critical"`
	Warning      int      `json:"warning"`
	Since        *string  `json:"since"`
	At           string   `json:"at"`
	Fingerprints []string `json:"fingerprints"`
}

// alertsFingerprintCap is what rides the beat. The rows are pulled on demand
// with observe:alerts; this is the count plus enough identity for the host to
// tell a new firing alert from the same one still firing.
const alertsFingerprintCap = 20

// alertsRefreshEvery is the background interval. One minute, matching the
// heartbeat's own tick (run.go:601), because an alert is the one signal in this
// family whose value is in arriving promptly; the fetch is a single HTTP GET
// against a service on this box's own network, not seven execs, so it costs
// nothing like the posture refresh does.
const alertsRefreshEvery = 60 * time.Second

var (
	alertsMu sync.Mutex
	// alertsRunning is the in-flight guard refreshDelta has and this did not
	// (deltarun.go:467-478 for the shape). run.go starts ONE refresher PER
	// PAIRING, so a box serving several hosts runs several of these in phase:
	// without the guard a slow goroutine holding an older summary can take
	// storeMu after a newer one and journal an alert as `firing` that the newer
	// pass just journalled as `cleared`. No entry is lost — every
	// read-modify-write of store-alerts.json is wholly inside storeMu — but the
	// journal's ORDER inverts, and a record whose order cannot be trusted is not
	// much of a record.
	alertsRunning bool
	alertsLast    *alertsSummary
)

func alertsPayload() *alertsSummary {
	alertsMu.Lock()
	defer alertsMu.Unlock()
	return alertsLast
}

// severityRank orders the fingerprints: critical first, then warning, then
// everything else. `severity` is the label Prometheus alert rules set; a value
// outside {critical, warning} counts in `firing` only, because inventing a
// bucket for it would put an unknown word in a count a human reads as a
// priority.
func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 0
	case "warning":
		return 1
	}
	return 2
}

// summarizeAlerts folds the typed set into the beat's summary. Deterministic
// by construction — sorted by severity, then oldest first, then fingerprint —
// so two beats over an unchanged Alertmanager carry an identical list and the
// host's change detection sees no movement where there was none.
// THE COUNTS READ `all`, NOT `Alerts`. Alerts is capped at 200 rows for the
// wire; counting from it made `firing` saturate silently, so 200 alerts and 400
// alerts produced an identical beat — the number an operator reads as severity,
// stuck. Counting is three increments per alert, so there is nothing to save by
// capping it. Only the fingerprint LIST stays bounded, at 20, because that is
// the part with a size on the wire. rep.all is empty for a report built by hand
// in a test, so it falls back to Alerts and the old call sites still mean what
// they said.
func summarizeAlerts(rep alertsReport, now time.Time) alertsSummary {
	s := alertsSummary{At: now.UTC().Format(time.RFC3339), Fingerprints: []string{}}
	from := rep.all
	if from == nil {
		from = rep.Alerts
	}
	ordered := append([]observedAlert(nil), from...)
	sort.SliceStable(ordered, func(i, j int) bool {
		ri, rj := severityRank(ordered[i].Severity), severityRank(ordered[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if ordered[i].StartsAt != ordered[j].StartsAt {
			return ordered[i].StartsAt < ordered[j].StartsAt
		}
		return ordered[i].Fingerprint < ordered[j].Fingerprint
	})
	var oldest time.Time
	for _, a := range ordered {
		// BELT AND BRACES WITH THE QUERY STRING, and deliberately so. The path
		// asks for active only, but a server-side filter is a request and this
		// is the box's own arithmetic: a silenced or inhibited alert that
		// arrives anyway — an older Alertmanager, a proxy that drops the query,
		// a future default change — must not be counted as firing. A silence is
		// an operator saying "I know, stop telling me", and the count that
		// reaches a human is the last place to honour it.
		if a.State != "" && a.State != "active" {
			continue
		}
		s.Firing++
		switch a.Severity {
		case "critical":
			s.Critical++
		case "warning":
			s.Warning++
		}
		if t, err := time.Parse(time.RFC3339, a.StartsAt); err == nil {
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
		if len(s.Fingerprints) < alertsFingerprintCap && a.Fingerprint != "" {
			s.Fingerprints = append(s.Fingerprints, a.Fingerprint)
		}
	}
	if !oldest.IsZero() {
		since := oldest.UTC().Format(time.RFC3339)
		s.Since = &since
	}
	return s
}

// refreshAlerts pulls the active set once and publishes the summary. Silent on
// every failure: an unreachable Alertmanager is the operator's problem to see
// through the op, not something a bastion should log on a loop every minute.
// The ctx is the heartbeat goroutine's LIFECYCLE context, not
// context.Background(): a shutdown cancels an in-flight fetch instead of
// leaving it to run out its own 20 s budget against a box that is going away.
//
// UNCONFIGURED AND FAILED ARE NOT THE SAME THING, and the cache has to tell
// them apart or it lies in one of two directions:
//
//   - A transient FAILURE keeps the last good summary. The alerts are still
//     firing; this box just cannot reach the Alertmanager this minute. Publishing
//     zeros would be an all-clear nobody can stand behind, and `at` going stale
//     is how the host sees the difference.
//   - UNCONFIGURED CLEARS IT. The admin removed the alertmanager key, so this
//     box is no longer watching anything and must stop claiming to. Keeping the
//     last value here froze a summary onto every beat until the process
//     restarted — the host would have gone on reading counts from an
//     Alertmanager this box had been told to forget. Clearing makes the key
//     absent again, which is the honest "did not look" state.
func refreshAlerts(parent context.Context) {
	alertsMu.Lock()
	if alertsRunning {
		alertsMu.Unlock()
		return
	}
	alertsRunning = true
	alertsMu.Unlock()
	defer func() {
		alertsMu.Lock()
		alertsRunning = false
		alertsMu.Unlock()
	}()

	ctx, cancel := opBudgetFrom(parent)
	defer cancel()
	raw, unconfigured, err := observePull(ctx, observeKeyAlertmanager, alertmanagerAlertsPath)
	if unconfigured != "" {
		alertsMu.Lock()
		alertsLast = nil
		alertsMu.Unlock()
		return
	}
	if err != nil {
		return
	}
	rep, err := parseAlerts(raw)
	if err != nil {
		return
	}
	s := summarizeAlerts(rep, time.Now())
	alertsMu.Lock()
	alertsLast = &s
	alertsMu.Unlock()
	// The alerts shelf of the machine store (machinestore.go). Written here and
	// not on the beat, because THIS is where a refresh actually happened: the
	// beat republishes the last value every time it fires, so journalling there
	// would record the beat's cadence rather than the alert set's changes.
	//
	// The failure is swallowed on purpose. An alerts refresh that cannot write
	// its journal must still publish its counts — the counts are what the host
	// reads to page somebody, and losing them to a full disk would turn a
	// storage problem into a blind fleet. The findings pass reports its own
	// store failures as a note on the beat and that is the channel that says
	// the store is unwell.
	_, _ = storeRecordAlerts(&s, time.Now())
}

// runAlertsRefresh is started beside runPostureRefresh by the heartbeat
// goroutine (run.go) and lives as long as it does. The beat NEVER waits on
// this: a late beat is what flips the box stale on the pod (ONLINE_WINDOW
// 180 s), so a beat serves the last published value and nothing else.
func runAlertsRefresh(ctx context.Context) {
	refreshAlerts(ctx)
	t := time.NewTicker(alertsRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refreshAlerts(ctx)
		}
	}
}
