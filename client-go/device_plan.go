package main

// device_plan.go — the approval device signing a ship plan (ops_plan.go).
//
// The pod files a DRAFT: the pipeline, the commit, the expiry, and the lines.
// The device makes the plan it will sign from it, filling in what only it may
// say:
//
//   - each machine's key, from its OWN pins (pin-machine, typed by the person
//     from what the machine printed when this device was pinned there) —
//     a machine the device has not pinned makes the whole plan unsignable;
//   - a fresh nonce, and a version one above the last it signed for that
//     pipeline, so a machine can refuse an older plan;
//   - whether the plan holds root work (any line with verbs), and, when it
//     does, that the person's code was checked HERE before signing.
//
// What the person reads is rendered from the plan itself, line by line: the
// machine, the op, its params, the verbs with their arguments, the inputs it
// takes from earlier steps, and whether a line may be undone or adopts the
// live image. The words and the signed bytes come from the same plan.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

const planDeviceVersionsFile = "device_plan_versions.json"

// devicePlanDraft is what the pod sends in a ship_plan ask's details.
type devicePlanDraft struct {
	Pipeline string         `json:"pipeline"`
	Commit   string         `json:"commit"`
	Expires  string         `json:"expires"`
	Lines    []shipPlanLine `json:"lines"`
}

// devicePlanFromDetails builds the plan this device would sign (without its
// version, nonce or code flag, which are set at signing) and checks it.
func devicePlanFromDetails(details map[string]any) (*shipPlan, error) {
	raw, err := json.Marshal(details["plan"])
	if err != nil {
		return nil, errors.New("the ask carries no plan")
	}
	var d devicePlanDraft
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, errors.New("the plan in the ask does not parse")
	}
	f, err := deviceKeyLoad()
	if err != nil || f.Pub == "" {
		return nil, errors.New("this machine is not an approval device (privatae-bastion device-init)")
	}
	pins := machinePinsLoad()
	p := &shipPlan{V: shipPlanVersion, Kind: shipPlanKind, Pipeline: d.Pipeline, Version: 1, Commit: d.Commit,
		Nonce: strings.Repeat("0", planNonceMin), Expires: d.Expires, Device: f.Pub, Machines: map[string]string{},
		Lines: d.Lines}
	for _, l := range d.Lines {
		key, ok := pins[l.Machine]
		if !ok {
			return nil, fmt.Errorf("this device has not pinned %s's key: pin it here first (privatae-bastion pin-machine %s <key>, with the key %s printed when you pinned this device there)", l.Machine, l.Machine, l.Machine)
		}
		p.Machines[l.Machine] = key
		if len(l.Verbs) > 0 {
			p.Root = true
		}
	}
	if err := planShape(p); err != nil {
		return nil, err
	}
	return p, nil
}

// devicePlanWords renders the plan for the person: what they approve, line by
// line, from the plan's own fields.
func devicePlanWords(p *shipPlan) string {
	var b strings.Builder
	exp, _ := time.Parse(time.RFC3339, p.Expires)
	fmt.Fprintf(&b, "Ship %s at commit %s: %d step(s), within %s.\n", wordsSafe(p.Pipeline), wordsSafe(truncate(p.Commit, 12)), len(p.Lines),
		time.Until(exp).Round(time.Minute))
	if p.Root {
		b.WriteString("It runs ROOT work on your machines (the steps marked root below): approving it needs your code.\n")
	}
	for _, l := range p.Lines {
		kind := "program only"
		if len(l.Verbs) > 0 {
			kind = "root"
		}
		fmt.Fprintf(&b, "%d. %s on %s: op %s (%s, %s) with %s\n", l.N, wordsSafe(l.Step), wordsSafe(l.Machine),
			wordsSafe(l.Op), wordsSafe(truncate(l.OpSHA256, 16)), kind, wordsSafe(l.Params))
		if l.Attempts > 1 {
			fmt.Fprintf(&b, "   may run up to %d times if it fails\n", l.Attempts)
		}
		names := make([]string, 0, len(l.Inputs))
		for n := range l.Inputs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			m := planInputRe.FindStringSubmatch(l.Inputs[n])
			if m == nil {
				continue
			}
			if m[2] != "" {
				fmt.Fprintf(&b, "   %s = the digest of %s that step %s builds\n", wordsSafe(n), wordsSafe(m[2]), wordsSafe(m[1]))
			} else {
				fmt.Fprintf(&b, "   %s = the digest step %s builds\n", wordsSafe(n), wordsSafe(m[1]))
			}
		}
		for _, v := range l.Verbs {
			keys := make([]string, 0, len(v.Args))
			for k := range v.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var args []string
			for _, k := range keys {
				args = append(args, wordsSafe(k)+"="+wordsSafe(v.Args[k]))
			}
			fmt.Fprintf(&b, "   %s %s\n", wordsSafe(v.Verb), strings.Join(args, " "))
		}
		if l.Undo {
			b.WriteString("   may be undone, to what that machine had before, if a later step fails\n")
		}
		if l.AdoptLive {
			b.WriteString("   FIRST ROLL: takes the image running now as its starting point, without checking its history\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// wordsSafe is a field as the person may read it: no control character, no
// line break, no Unicode format or direction character, which could redraw,
// hide or reorder what they read. The plan's form refuses them already
// (planShape); this is what the words do whatever reached them.
func wordsSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			b.WriteRune('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// planPurpose names a plan ask for de-duplication: the same draft from the
// same pod is the same ask.
func planPurpose(p *shipPlan) string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return shipPlanKind + "|" + p.Pipeline + "|" + hex.EncodeToString(sum[:])
}

// devicePlanSign signs the plan of an approved ask: a fresh nonce, the next
// version for the pipeline, and — for a root plan — the code, checked here
// against the factor enrolled on the pairing the ask came in on.
func devicePlanSign(r deviceRequest, code string) (string, error) {
	p, err := devicePlanFromDetails(r.Details)
	if err != nil {
		return "", err
	}
	if p.Root {
		if strings.TrimSpace(code) == "" {
			return "", errors.New("this plan runs root work: approve it with your code")
		}
		dir, err := deviceFactorDir()
		if err != nil {
			return "", err
		}
		if _, err := stepupVerifyAndBurn(dir, code, time.Now()); err != nil {
			return "", fmt.Errorf("your code: %v", err)
		}
		p.CodeGiven = true
	}
	f, err := deviceKeyLoad()
	if err != nil || f.Priv == "" {
		return "", errors.New("this machine holds no device key")
	}
	priv, err := base64.StdEncoding.DecodeString(f.Priv)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("bad device key file")
	}
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	p.Nonce = hex.EncodeToString(n)
	v, err := deviceNextPlanVersion(p.Pipeline)
	if err != nil {
		return "", err
	}
	p.Version = v
	if err := planShape(p); err != nil {
		return "", err
	}
	body, _ := json.Marshal(p)
	env := shipPlanEnvelope{PayloadType: shipPlanPayloadType, Payload: base64.StdEncoding.EncodeToString(body),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), dssePAE(shipPlanPayloadType, body)))}
	out, _ := json.Marshal(env)
	return string(out), nil
}

// deviceFactorDir is where the person's own factor for this device is
// enrolled: the anchor pairing's (the device lane answers only its anchor,
// deviceLaneOnly), or the only pairing of an unanchored device. Never a
// folder the ask names: the pod sends the ask.
func deviceFactorDir() (string, error) {
	cfgs, err := loadPairings()
	if err != nil {
		return "", errors.New("this device's pairings cannot be read, so there is no factor to check your code against")
	}
	var pick *Config
	if a := currentAnchor(); a != nil {
		for _, c := range cfgs {
			if c != nil && c.HostName == a.AnchorHost {
				pick = c
			}
		}
	} else if len(cfgs) == 1 {
		pick = cfgs[0]
	}
	if pick == nil {
		return "", errors.New("this device has no pairing its factor belongs to (anchor it, or keep one pairing)")
	}
	dir := pick.dcnDir()
	if dir == "" {
		return "", errors.New("this device's pairing has no folder for its factor")
	}
	return dir, nil
}

// deviceNextPlanVersion is one above the last version this device signed for
// the pipeline, recorded before it is used.
func deviceNextPlanVersion(pipeline string) (int64, error) {
	m := planLedgerLoad(planDeviceVersionsFile)
	var v int64
	_, _ = fmt.Sscan(m[pipeline], &v)
	v++
	m[pipeline] = fmt.Sprint(v)
	if err := planLedgerSave(planDeviceVersionsFile, m); err != nil {
		return 0, fmt.Errorf("could not record the plan's version: %v", err)
	}
	return v, nil
}

// devicePlanLive: a signed plan envelope whose plan has not expired.
func devicePlanLive(approval string, now time.Time) bool {
	var env shipPlanEnvelope
	if json.Unmarshal([]byte(strings.TrimSpace(approval)), &env) != nil || env.PayloadType != shipPlanPayloadType {
		return false
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return false
	}
	var p shipPlan
	if json.Unmarshal(body, &p) != nil {
		return false
	}
	exp, err := time.Parse(time.RFC3339, p.Expires)
	return err == nil && exp.After(now)
}

// deviceNewPlanRequest files a ship_plan ask. A root plan's code is checked,
// when the person approves, against the factor enrolled on this device's own
// pairing (deviceFactorDir), never one the ask names.
func deviceNewPlanRequest(details map[string]any) (string, error) {
	p, err := devicePlanFromDetails(details)
	if err != nil {
		return "", err
	}
	purpose := planPurpose(p)
	machines := make([]string, 0, len(p.Machines))
	for h := range p.Machines {
		machines = append(machines, h)
	}
	sort.Strings(machines)
	server := strings.Join(machines, ", ")
	deviceMu.Lock()
	defer deviceMu.Unlock()
	m := deviceRequestsLoad()
	for _, r := range m {
		if r.Purpose == purpose && r.State == "denied" {
			return "", errors.New("you refused this on your device; it cannot be asked again for 24h")
		}
	}
	for id, r := range m {
		if r.Purpose == purpose && (r.State == "pending" || (r.State == "approved" && !r.Delivered && devicePlanLive(r.Approval, time.Now()))) {
			return id, nil
		}
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	m[id] = deviceRequest{Purpose: purpose, Words: devicePlanWords(p), Server: server, Details: details,
		At: time.Now().UTC().Format(time.RFC3339), State: "pending", Plan: true, NeedsCode: p.Root}
	if err := deviceRequestsSave(m); err != nil {
		return "", err
	}
	return id, nil
}

// cmdPinMachine / cmdUnpinMachine: the person, at their device.
func cmdPinMachine(host, key string, unpin bool) error {
	if _, err := deviceKeyLoad(); err != nil {
		return errors.New("this machine is not an approval device (privatae-bastion device-init)")
	}
	if unpin {
		if err := unpinMachineKey(host); err != nil {
			return err
		}
		fmt.Printf("%s unpinned; this device signs no plan for it until it is pinned again\n", host)
		return nil
	}
	if err := pinMachineKey(host, key); err != nil {
		return err
	}
	fmt.Printf("%s pinned; this device may now sign ship plans that include it\n", host)
	return nil
}

// machineKeyLine is what a machine prints when this device is pinned there:
// the command the person runs on the device to pin the machine back.
func machineKeyLine() string {
	pub, _, err := loadOrCreateOwnerKey()
	if err != nil {
		return ""
	}
	hn, _ := os.Hostname()
	return "privatae-bastion pin-machine " + hn + " " + base64.StdEncoding.EncodeToString(pub)
}
