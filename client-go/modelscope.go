package main

// Per-model scoping of the inference forwards.
//
// THE SENTENCE THIS FILE HAS TO MAKE TRUE. Someone shares one model off their
// own machine with a friend's host, and the friend must be able to say: "the
// only thing we can do with this machine is use the qwen4 model." Before this,
// the smallest thing an anchor could grant was the whole `inference` family —
// every model ollama has loaded, the OpenAI-compatible server beside it, and
// the PII sterilizer — so that sentence was false in three different ways.
//
// The scope rides in the anchor's SIGNED grant terms as `models`, beside
// `caps`. Absent or empty = UNSCOPED, which is exactly today's behaviour and
// what every grant signed before this field existed carries. A non-empty list
// is a ceiling on top of the `inference` cap: deny-by-default, like caps.
//
// Where it is enforced, and why not at accept. The forwards are raw TCP
// splices (run.go, pii.go) and a model name lives in the HTTP request BODY, so
// there is nothing to check at accept time — a connection carries no model.
// Enforcement is therefore one layer in: inferencefilter.go terminates HTTP on
// the forward when a scope is in force, checks the named model per request, and
// filters the model LISTS on the way back so the friend's host is never offered
// a model it would then be refused. agents.go applies the same filter to the
// heartbeat, for the same reason it withholds the lanes outside `inference`:
// advertising what will be refused is a lie about reachability.
//
// THE PII LANE IS NOT A MODEL. The sterilizer (pii.go) is a bearer-authed
// service, not something ollama serves, so no model name can name it and a
// scoped grant refuses it by default. The one reserved entry `pii` includes it.
// That cannot collide with a model: ollama's own names always carry a tag
// (`qwen3:4b`, `all-minilm:latest`), so a bare `pii` is never one of them.

import "strings"

// piiScopeEntry is the reserved entry in a grant's `models` list that includes
// the PII sterilization lane. Named, never implied — that is the rule for this
// grant shape: a scoped pairing gets the models it was given and nothing else.
const piiScopeEntry = "pii"

// modelScope is what one pairing may reach on the inference lanes of THIS box.
//
//	scoped=false  the grant named no models: every loaded model, and the PII
//	              lane if the box runs one. The contract from before `models`
//	              existed, unchanged.
//	scoped=true   only `models`, and PII only if `pii` was named.
type modelScope struct {
	scoped bool
	models []string
	pii    bool
}

// unscopedModels is the ceiling-free scope: what the anchor pairing holds, what
// an unanchored local box hands its one host, and what every grant signed
// before `models` existed means.
func unscopedModels() modelScope { return modelScope{} }

// pairingModelScope is the scope for one pairing, read from its VERIFIED grant
// on every call (like capsAllow — a re-approval that narrows the list must take
// effect without a restart, and a tampered grant file must authorise nothing).
//
// Fails CLOSED in one direction only: a pairing with no verifiable grant is
// already refused the whole `inference` family by capsAllow, so the scope it
// gets here never decides anything. Returning unscoped for it would be a lie
// waiting for a caller that forgot the caps check, so it returns an EMPTY
// scoped list — the narrowest possible answer.
func pairingModelScope(self string) modelScope {
	a := currentAnchor()
	if a == nil {
		// Unanchored: a local box gates nothing (the pairing IS the
		// authorization there), and an unanchored networked box never reaches
		// a forward at all — unanchoredNetworkedRefusal closes it in capsAllow.
		return unscopedModels()
	}
	if self == "" {
		return modelScope{scoped: true}
	}
	if a.AnchorHost == self {
		return unscopedModels() // the anchor user is the machine's admin
	}
	t, ok := pairingGrantTerms(self)
	if !ok {
		return modelScope{scoped: true}
	}
	return scopeFromTerms(t.Models)
}

// scopeFromTerms turns the signed `models` list into a scope. Kept separate
// from the grant read so the signed-bytes → policy step is testable on its own.
// A PRESENT list is a scope, even if nothing in it survives trimming. The first
// cut set `scoped` only when it kept an entry, so a grant carrying ["", " "]
// came out UNSCOPED — a malformed ceiling failing open into no ceiling at all.
// The anchor host signs these, so it was never likely; it was still the wrong
// direction to fail in.
func scopeFromTerms(models []string) modelScope {
	s := modelScope{scoped: len(models) > 0}
	for _, m := range models {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" {
			continue
		}
		if m == piiScopeEntry {
			s.pii = true
			continue
		}
		s.models = append(s.models, m)
	}
	return s
}

// allowsPII answers the one question the PII forward asks.
func (s modelScope) allowsPII() bool { return !s.scoped || s.pii }

// allowsModel matches a model name from a request or a model list against the
// scope. Matching is EXACT, with one equivalence: ollama's default tag, so a
// grant naming `all-minilm` admits `all-minilm:latest` and the reverse. A bare
// repo name never admits another tag — `qwen3` does not open `qwen3:70b`, which
// would be a silent widening of what the user read when they approved.
func (s modelScope) allowsModel(name string) bool {
	if !s.scoped {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(name))
	if want == "" {
		return false
	}
	for _, m := range s.models {
		if m == want || defaultTagEq(m, want) {
			return true
		}
	}
	return false
}

// defaultTagEq: "x" and "x:latest" are the same model to ollama.
func defaultTagEq(a, b string) bool {
	return a+":latest" == b || b+":latest" == a
}

// filterModels keeps only the names this scope allows, preserving order. Used
// on every list that leaves this box for a scoped pairing — the heartbeat's
// model lists (agents.go) and the /api/tags, /v1/models responses the forward
// proxies back (inferencefilter.go).
func (s modelScope) filterModels(names []string) []string {
	if !s.scoped {
		return names
	}
	out := []string{}
	for _, n := range names {
		if s.allowsModel(n) {
			out = append(out, n)
		}
	}
	return out
}

// describe is the refusal sentence: what this pairing may actually use. Named
// in the 403 the filter returns, so the friend's host is told the truth rather
// than left to guess at a model that "does not exist".
func (s modelScope) describe() string {
	if !s.scoped {
		return "every model on this machine"
	}
	if len(s.models) == 0 {
		return "no models"
	}
	return strings.Join(s.models, ", ")
}
