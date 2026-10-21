package main

// observe-endpoints.json — the neighbourhood the box is allowed to READ.
//
// observe:alerts, observe:metrics and observe:logs are HTTP reads of services
// that run beside this box: an Alertmanager, a Prometheus, a Loki. Nothing is
// exec'd, so the sudoers discipline the rest of the family lives by shows up
// here as a different wall: the HOST never names a URL. The admin places one
// file at install and the box will talk to those three addresses and nowhere
// else; the host's only argument is a NAME out of a fixed table.
//
// This follows observeKubeconfig (observe_ops.go:457) exactly: a file the
// installer places, never this code, and an op that says so plainly when it is
// absent rather than inventing a value. observe:k8s answers
// {"supported":false,"reason":...} with exit 0 (readK8s, observe_ops_linux.go:302-306)
// because "this box cannot say" is a true answer and 126 means "not permitted";
// the three ops here answer in the same shape, with the same exit code.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// observeEndpointsPath is placed by the admin at install, beside the read-only
// kubeconfig observe:k8s reads. A var, not a const, only so the tests can point
// it at a temp file; nothing in the product ever assigns it.
var observeEndpointsPath = "/etc/privatae-bastion/observe-endpoints.json"

// observeEndpoints is the whole file: three optional keys, each a base URL.
//
//	{"alertmanager":"http://192.0.2.10:9093",
//	 "prometheus":"http://192.0.2.11:9090",
//	 "loki":"http://192.0.2.12:3100"}
//
// IP literals are the common case, because a host-network process on many
// platforms cannot resolve cluster-internal service names — a name is
// accepted too, but it has to resolve here and every address it resolves to
// has to pass the check below.
type observeEndpoints struct {
	Alertmanager string `json:"alertmanager"`
	Prometheus   string `json:"prometheus"`
	Loki         string `json:"loki"`
}

func (e observeEndpoints) get(key string) string {
	switch key {
	case observeKeyAlertmanager:
		return e.Alertmanager
	case observeKeyPrometheus:
		return e.Prometheus
	case observeKeyLoki:
		return e.Loki
	}
	return ""
}

const (
	observeKeyAlertmanager = "alertmanager"
	observeKeyPrometheus   = "prometheus"
	observeKeyLoki         = "loki"
)

// errEndpointsAbsent is the "the admin has not placed the file" case, which is
// NOT an error the host should see as a refusal — it is the unconfigured
// answer. Kept as a sentinel so the handlers can tell it from a malformed file,
// which IS a refusal.
var errEndpointsAbsent = errors.New("absent")

// THE REFUSAL LIST IS INVERTED HERE, ON PURPOSE.
//
// observe:net refuses every non-public address (nonPublicRanges,
// observe_ops.go:617-624): its job is an outside-in probe of a NAMED PUBLIC
// DOOR, and a probe of a mesh or LAN address from a fleet box is a different
// tool. These three ops are that different tool. Their whole point is reading
// the box's own neighbourhood — a ClusterIP, a loopback port, a mesh address —
// so loopback, RFC1918, CGNAT, link-local and ULA are exactly what is ALLOWED,
// and a PUBLIC address is what is refused.
//
// The refusal is not symmetry for its own sake. Without it this file is a way
// to make the box fetch the internet on the host's behalf: place one URL and
// every `observe:alerts` becomes an outbound GET to somebody else's server,
// from inside the perimeter, with the box's own identity. The endpoints file is
// an admin's declaration of what is NEXT TO this machine, and nothing else.
func observeEndpointAllowed(a netip.Addr) bool { return !isPublicAddr(a) }

// validateObserveEndpoint checks one key's URL and returns the normalized base.
// Every failure names the key, because the admin reading the message has three
// of them in one file.
func validateObserveEndpoint(ctx context.Context, key, raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New(key + ": not a URL: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New(key + `: scheme must be http or https, got "` + u.Scheme + `"`)
	}
	if u.User != nil {
		return "", errors.New(key + ": credentials in the URL are not accepted")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New(key + ": the endpoint is a base URL — no query, no fragment")
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return "", errors.New(key + ": the endpoint is a base URL — no path, the op owns the path")
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New(key + ": no host")
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		// A hostname is allowed, and it is resolved HERE so the check below has
		// something to judge. Same all-must-pass rule as publicTarget
		// (observe_ops.go:646-667), inverted: one public record among private
		// ones is enough to turn the op outward, so all must be private.
		resolved, err := netResolve(ctx, host)
		if err != nil {
			return "", errors.New(key + ": resolve " + host + ": " + err.Error())
		}
		if len(resolved) == 0 {
			return "", errors.New(key + ": resolve " + host + ": no addresses")
		}
		addrs = resolved
	}
	for _, a := range addrs {
		if !observeEndpointAllowed(a) {
			return "", errors.New(key + ": " + a.Unmap().String() +
				" is a public address — these ops read this box's own neighbourhood only")
		}
	}
	port := u.Port()
	if port != "" {
		if _, err := net.LookupPort("tcp", port); err != nil {
			return "", errors.New(key + ": bad port " + port)
		}
	}
	// THE HOSTNAME IS RETURNED UNRESOLVED, AND THAT IS A TOCTOU BY CONSTRUCTION.
	// The addresses checked just above came from a resolution that happened
	// HERE; the transport resolves again when it dials, and between the two the
	// answer can change — DNS rebinding, a short TTL, a split-horizon resolver
	// that answers differently per query. Returning the resolved literal instead
	// would not fix it: it would pin an address and break every endpoint behind
	// a name that legitimately moves, and it would still be one resolution
	// earlier than the socket.
	//
	// The gap is closed one layer down, where it cannot be raced:
	// observeDialControl (observe_pull.go) re-checks observeEndpointAllowed
	// against the address the socket is ABOUT TO CONNECT TO, after the
	// transport's own resolution and before connect. This check stays because it
	// gives the admin a clear, named error at the point of a typo; the dial
	// control is what actually holds the wall.
	return u.Scheme + "://" + u.Host, nil
}

// loadObserveEndpoints reads and validates the file. errEndpointsAbsent when it
// is not there; a named error when it is there and wrong. Read per call rather
// than cached: the admin edits the file, and an op that answered from a cache
// would keep reporting an address the admin has already removed.
func loadObserveEndpoints(ctx context.Context) (observeEndpoints, error) {
	var e observeEndpoints
	raw, err := os.ReadFile(observeEndpointsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return e, errEndpointsAbsent
		}
		return e, errors.New("observe-endpoints.json: " + err.Error())
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return e, errors.New("observe-endpoints.json: " + err.Error())
	}
	for _, key := range []string{observeKeyAlertmanager, observeKeyPrometheus, observeKeyLoki} {
		v := e.get(key)
		if strings.TrimSpace(v) == "" {
			continue
		}
		norm, err := validateObserveEndpoint(ctx, key, v)
		if err != nil {
			return observeEndpoints{}, errors.New("observe-endpoints.json: " + err.Error())
		}
		switch key {
		case observeKeyAlertmanager:
			e.Alertmanager = norm
		case observeKeyPrometheus:
			e.Prometheus = norm
		case observeKeyLoki:
			e.Loki = norm
		}
	}
	return e, nil
}

// observeEndpointFor resolves ONE key to a base URL, with the three answers the
// handlers need kept apart: configured, unconfigured (absent file or absent
// key — reported, not refused), refused (a file that is there and wrong).
func observeEndpointFor(ctx context.Context, key string) (base string, unconfigured string, err error) {
	e, err := loadObserveEndpoints(ctx)
	if errors.Is(err, errEndpointsAbsent) {
		return "", "unconfigured: no endpoints file at " + observeEndpointsPath, nil
	}
	if err != nil {
		return "", "", err
	}
	base = e.get(key)
	if base == "" {
		return "", "unconfigured: " + observeEndpointsPath + ` names no "` + key + `"`, nil
	}
	return base, "", nil
}
