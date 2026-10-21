package main

// coders_cli.go — `privatae-bastion coders ...`: the owner sizes this machine
// for coder runs (coders.go). Machine-wide, stored in <configDir>/coders/config.json.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const codersUsage = `usage:
  privatae-bastion coders set [--max N] [--mem MB] [--cpus F] [--engines a,b|all] [--allow-lan host[:port],...]
                              [--image-prefix <registry/path/>|default]
  privatae-bastion coders on | off
  privatae-bastion coders drop [--host H]
  privatae-bastion coders status [--json]`

func cmdCoders(args []string) error {
	if len(args) == 0 {
		return errors.New(codersUsage)
	}
	switch args[0] {
	case "set":
		return cmdCodersSet(args[1:])
	case "on":
		c, err := coderTurnOn(loadCoderConfig())
		if err != nil {
			return err
		}
		fmt.Printf("coder runs ON: up to %d at a time, %d MiB and %s CPUs each, engines %s\n",
			c.Max, c.MemPerRun, strconv.FormatFloat(c.CPUsPerRun, 'f', -1, 64), strings.Join(c.Engines, ","))
		return nil
	case "off":
		c := loadCoderConfig()
		c.Enabled = false
		if err := saveCoderConfig(c); err != nil {
			return err
		}
		fmt.Println("coder runs OFF: no new run starts here; runs already going continue until they are stopped or reaped")
		return nil
	case "drop":
		host, rest := takeHostFlag(args[1:])
		if len(rest) != 0 {
			return errors.New(codersUsage)
		}
		return cmdCodersDrop(host)
	case "status":
		asJSON := len(args) > 1 && args[1] == "--json"
		return cmdCodersStatus(asJSON)
	}
	return errors.New(codersUsage)
}

// coderApplySet parses `coders set` flags onto c. Bounds: max 1..100, mem
// 512..65536, cpus 0.25..NumCPU, engines a subset of the coding engines.
func coderApplySet(c coderConfig, args []string, numCPU int) (coderConfig, error) {
	if len(args) == 0 {
		return c, errors.New(codersUsage)
	}
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if i+1 >= len(args) {
			return c, fmt.Errorf("%s needs a value", flag)
		}
		v := args[i+1]
		i++
		switch flag {
		case "--max":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 100 {
				return c, errors.New("--max must be 1-100")
			}
			c.Max = n
		case "--mem":
			n, err := strconv.Atoi(v)
			if err != nil || n < 512 || n > 65536 {
				return c, errors.New("--mem must be 512-65536 (MiB per run)")
			}
			c.MemPerRun = n
		case "--cpus":
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0.25 || f > float64(numCPU) {
				return c, fmt.Errorf("--cpus must be 0.25-%d", numCPU)
			}
			c.CPUsPerRun = f
		case "--engines":
			if v == "all" {
				c.Engines = append([]string(nil), coderEngines...)
				break
			}
			var eng []string
			for _, e := range strings.Split(v, ",") {
				e = strings.TrimSpace(e)
				if e == "" {
					continue
				}
				if !isCoderEngine(e) {
					return c, fmt.Errorf("--engines: %q is not a coding engine (%s)", e, strings.Join(coderEngines, ", "))
				}
				if !containsStr(eng, e) {
					eng = append(eng, e)
				}
			}
			if len(eng) == 0 {
				return c, errors.New("--engines names no engine")
			}
			c.Engines = eng
		case "--allow-lan":
			var allow []string
			for _, h := range strings.Split(v, ",") {
				h = strings.TrimSpace(h)
				if h == "" {
					continue
				}
				if strings.ContainsAny(h, " /\t") {
					return c, fmt.Errorf("--allow-lan: %q is not a host[:port]", h)
				}
				if hh, p, err := net.SplitHostPort(h); err == nil {
					if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 || hh == "" {
						return c, fmt.Errorf("--allow-lan: %q has a bad port", h)
					}
				}
				allow = append(allow, h)
			}
			c.AllowLAN = allow
		case "--image-prefix":
			// Where run images may come from: <prefix>harness-<engine>@sha256:...
			// "default" (or the default itself) clears it, so the file holds
			// only a prefix the owner chose.
			if v == "default" || v == coderDefaultImagePrefix {
				c.ImagePrefix = ""
				break
			}
			if why := coderPrefixRefusal(v); why != "" {
				return c, errors.New(why)
			}
			c.ImagePrefix = v
		default:
			return c, fmt.Errorf("unknown flag %s\n%s", flag, codersUsage)
		}
	}
	return c, nil
}

func cmdCodersSet(args []string) error {
	c, err := coderApplySet(loadCoderConfig(), args, runtime.NumCPU())
	if err != nil {
		return err
	}
	if err := saveCoderConfig(c); err != nil {
		return err
	}
	fmt.Println("coder settings saved (on/off unchanged: `privatae-bastion coders on`)")
	return nil
}

// coderTurnOn fills every unset value with its default and enables. max
// defaults to how many runs fit in the memory budget (coderBudgetMB),
// clamped to 1..100, and refuses when the machine cannot hold one run.
func coderTurnOn(c coderConfig) (coderConfig, error) {
	if c.MemPerRun == 0 {
		c.MemPerRun = coderDefaultMemMB
	}
	if c.CPUsPerRun == 0 {
		c.CPUsPerRun = coderDefaultCPUs
		if n := float64(runtime.NumCPU()); c.CPUsPerRun > n {
			c.CPUsPerRun = n
		}
	}
	if len(c.Engines) == 0 {
		c.Engines = append([]string(nil), coderEngines...)
	}
	if c.Max == 0 {
		total, _, ok := coderMemInfo()
		if !ok {
			return c, errors.New("cannot read this machine's memory; set it with `coders set --max N`")
		}
		n := coderBudgetMB(int(total>>20)) / c.MemPerRun
		if n < 1 {
			return c, fmt.Errorf("this machine has %d MiB; one run of %d MiB plus %d MiB for the machine does not fit",
				total>>20, c.MemPerRun, coderReserveMB(int(total>>20)))
		}
		if n > 100 {
			n = 100
		}
		c.Max = n
	}
	c.Enabled = true
	return c, saveCoderConfig(c)
}

// cmdCodersDrop deletes the standing coder grant(s) of every pairing, or of
// host, and stops those pairings' runs here.
func cmdCodersDrop(host string) error {
	cfgs, err := loadPairings()
	if err != nil {
		return err
	}
	var targets []*Config
	if host != "" {
		c, err := findPairing(cfgs, host)
		if err != nil {
			return err
		}
		if c == nil {
			return fmt.Errorf("no pairing for %q (paired: %s)", host, strings.Join(hostNames(cfgs), ", "))
		}
		targets = []*Config{c}
	} else {
		targets = cfgs
	}
	owners := map[string]bool{}
	for _, c := range targets {
		owners[c.HostName] = true
		ids, err := coderGrantDropAll(c.dcnDir(), "dropped at this machine (coders drop)")
		if err != nil {
			return fmt.Errorf("%s: %w", c.HostName, err)
		}
		fmt.Printf("%s: %d coder grant(s) dropped\n", c.HostName, len(ids))
	}
	rt := coderRuntime()
	stopped, failed := 0, 0
	for _, r := range loadCoderRecords() {
		if !owners[r.Owner] {
			continue
		}
		if rt == "" {
			failed++
			continue
		}
		r := r
		if _, err := coderTeardown(rt, r.RunID, &r); err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "run %s: %v\n", r.RunID, err)
			continue
		}
		stopped++
	}
	fmt.Printf("%d run(s) stopped", stopped)
	if failed > 0 {
		fmt.Printf(", %d could not be confirmed stopped (the reaper retries)", failed)
	}
	fmt.Println()
	return nil
}

func cmdCodersStatus(asJSON bool) error {
	c := loadCoderConfig()
	cfgs, _ := loadPairings()
	type grantView struct {
		Host    string   `json:"host"`
		Engines []string `json:"engines"`
		Max     int      `json:"max"`
		Expires string   `json:"expires"`
	}
	grants := []grantView{}
	for _, p := range cfgs {
		dir := p.dcnDir()
		f, err := dcnLoadFile(dir)
		if err != nil {
			continue
		}
		for _, rec := range f.Coder {
			raw, err := base64.StdEncoding.DecodeString(rec.TermsCanonical)
			var t coderTerms
			if err != nil || json.Unmarshal(raw, &t) != nil {
				continue
			}
			grants = append(grants, grantView{Host: p.HostName, Engines: t.Engines, Max: t.Max, Expires: t.Expires})
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Host < grants[j].Host })
	runs := coderReports("", true)
	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{"config": c, "grants": grants, "runs": runs}, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	state := "OFF"
	if c.Enabled {
		state = "ON"
	}
	fmt.Printf("coder runs: %s  max %d  %d MiB / %s CPUs per run  engines %s\n", state, c.Max, c.MemPerRun,
		strconv.FormatFloat(c.CPUsPerRun, 'f', -1, 64), strings.Join(c.Engines, ","))
	if total, _, ok := coderMemInfo(); ok && c.MemPerRun > 0 {
		mb := int(total >> 20)
		fmt.Printf("memory for runs: %d of %d MiB (%d kept for the machine), so %d run(s) of %d MiB at a time\n",
			coderBudgetMB(mb), mb, coderReserveMB(mb), max(coderBudgetMB(mb)/c.MemPerRun, 0), c.MemPerRun)
	}
	if len(c.AllowLAN) > 0 {
		fmt.Printf("LAN hosts runs may reach: %s\n", strings.Join(c.AllowLAN, ", "))
	}
	fmt.Printf("run images: %sharness-<engine>@sha256:<digest>\n", c.imagePrefix())
	for _, g := range grants {
		fmt.Printf("grant: %s  engines %s  max %d  until %s\n", g.Host, strings.Join(g.Engines, ","), g.Max, g.Expires)
	}
	now := time.Now()
	for _, r := range runs {
		left := ""
		if dl, err := time.Parse(time.RFC3339, r.Deadline); err == nil {
			left = dl.Sub(now).Round(time.Minute).String() + " left"
		}
		fmt.Printf("run %s  %s  %s  port %d  %s\n", r.RunID, r.Engine, r.State, r.TunnelPort, left)
		if r.StoppedBy != "" {
			fmt.Printf("    stopped to protect this machine: %s\n", r.StoppedBy)
		}
	}
	if len(runs) == 0 {
		fmt.Println("no runs on this machine")
	}
	return nil
}
