//go:build linux

package main

// Linux drivers for observe:*. Each reads a file under /proc, /run, /var or
// runs ONE fixed argv through observeExec — the same read-only forms a
// read-only sudoers policy pins (nft list …, ss -tlnp, dmesg -T, ufw status, …).
// Nothing in this file touches a job argument. Every op's execs share one
// budget (opBudget); a field whose exec ran out of it is marked "timeout"
// and the op still answers.

import (
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const observeHostSupported = true

// textOf runs a fixed argv and returns its stdout and whether the op budget
// ran out during it. stderr and a non-zero exit are not errors here: nft
// with no such table exits 1 with nothing on stdout, and "" is what the
// parser turns into "absent".
func textOf(ctx context.Context, name string, args ...string) (string, bool) {
	out, _ := observeExec(ctx, name, args...)
	return string(out), ctx.Err() != nil
}

// readHostPosture is the host's probe, run natively. Each field's rule and
// vocabulary are documented on hostPosture (observe_ops.go).
func readHostPosture() hostPosture {
	ctx, cancel := opBudget()
	defer cancel()
	p := hostPosture{Ufw: "absent", Pubwall: "absent", Ssh22: "unknown", F2b: "absent",
		Input: "absent", Sec: -1, Load: -1, Cpus: runtime.NumCPU(), Reboot: "no", DiskPct: -1,
		Jrn: -1, Puv: "absent"}
	timedOut := func(field string) { p.Timeouts = append(p.Timeouts, field) }

	haveUfw := observeHave("ufw")
	ufwStatus := ""
	if haveUfw {
		var late bool
		ufwStatus, late = textOf(ctx, "ufw", "status")
		p.Ufw = parseUfwStatus(ufwStatus)
		if late {
			p.Ufw = "timeout"
			timedOut("ufw")
		}
	}
	nftTable := ""
	if observeHave("nft") {
		chain, late := textOf(ctx, "nft", "list", "chain", "inet", "pubwall", "input")
		p.Pubwall = parsePubwall(chain)
		if late {
			p.Pubwall = "timeout"
			timedOut("pubwall")
		}
		nftTable, late = textOf(ctx, "nft", "list", "table", "inet", "pubwall")
		if late {
			timedOut("ssh22")
		}
	}
	p.Ssh22 = parseSSH22(nftTable, ufwStatus, haveUfw)
	if ctx.Err() != nil {
		p.Ssh22 = "timeout"
	}
	if observeHave("systemctl") {
		// is-active exits non-zero for anything but "active" and still prints
		// the word; Output() returns both, so read the text regardless.
		out, late := textOf(ctx, "systemctl", "is-active", "fail2ban")
		switch {
		case late:
			p.F2b = "timeout"
			timedOut("f2b")
		case strings.TrimSpace(out) != "":
			p.F2b = strings.TrimSpace(out)
		default:
			p.F2b = "unknown"
		}
	}
	if observeHave("iptables") {
		out, late := textOf(ctx, "iptables", "-S")
		p.Input = parseIptablesInputPolicy(out)
		if late {
			p.Input = "timeout"
			timedOut("input")
		}
	}
	if observeHave("apt-get") {
		// The error is read for THIS field: an apt that failed or printed
		// nothing must count -1, never 0 (parseAptSecurityCount says why).
		out, err := observeExec(ctx, "apt-get", "-s", "upgrade")
		switch {
		case ctx.Err() != nil:
			timedOut("sec")
		case err != nil && len(out) == 0:
			p.Sec = -1
		default:
			p.Sec = parseAptSecurityCount(string(out))
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		p.Load = parseLoadavg(string(b))
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		p.Reboot = "yes"
	}
	p.DiskPct = statfsPct("/")
	if observeHave("journalctl") {
		out, late := textOf(ctx, "journalctl", "-n1", "-o", "short-unix", "--no-pager")
		if late {
			timedOut("jrn")
		} else {
			p.Jrn = parseJournalAge(out, time.Now())
		}
	}
	if b, err := os.ReadFile("/run/privatae/post-upgrade-verify.status"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			p.Puv = f[0]
		}
	}
	return p
}

// statfsPct is the percent `df -P` prints for a mount: used over
// (used + available to unprivileged users), rounded UP — df's own arithmetic,
// so this field agrees with the df column an operator compares it to.
func statfsPct(path string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return -1
	}
	used := st.Blocks - st.Bfree
	total := used + st.Bavail
	if total == 0 {
		return -1
	}
	return int((used*100 + total - 1) / total)
}

type socketsReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Partial   string `json:"partial,omitempty"` // which half ran out of budget
	// Failed is a half that RAN and exited non-zero. Separate from Partial
	// because a timeout and a failure are different operator problems, and
	// separate from Reason because the binary was there and did run.
	Failed  string         `json:"failed,omitempty"`
	Sockets []listenSocket `json:"sockets"`
}

// A FAILED `ss` IS NOT AN EMPTY SOCKET TABLE, and textOf cannot tell the
// caller which it got. It is `out, _ := observeExec(...)` on purpose — nft
// exits 1 with empty stdout for "no such table" and "" is the right answer
// there — but on this path an empty table becomes the DEFINITION OF NORMAL the
// next accounting is taken from, and then every listener on the box reports
// gone or new depending on which side was blind. Measured:
// an `ss` that exits non-zero produced 54 of 54 listeners reported gone, with
// no note. exec.Cmd.Output also returns partial stdout WITH the error, so a
// truncated run reads as a complete short table unless the error is checked.
//
// So this path checks it, and only this path: textOf keeps its contract for
// every other op that legitimately reads "" as absent.
func readSockets() socketsReport {
	if !observeHave("ss") {
		return socketsReport{Reason: "ss not installed", Sockets: []listenSocket{}}
	}
	ctx, cancel := opBudget()
	defer cancel()
	r := socketsReport{Supported: true}
	tcp, tcpErr := observeExec(ctx, "ss", "-tlnpH")
	r.Sockets = parseSS("tcp", string(tcp))
	if ctx.Err() != nil {
		r.Partial = "tcp: timeout"
		return r
	}
	if tcpErr != nil {
		r.Failed = "tcp: " + tcpErr.Error()
		return r
	}
	udp, udpErr := observeExec(ctx, "ss", "-ulnpH")
	r.Sockets = append(r.Sockets, parseSS("udp", string(udp))...)
	if ctx.Err() != nil {
		r.Partial = "udp: timeout"
	} else if udpErr != nil {
		r.Failed = "udp: " + udpErr.Error()
	}
	return r
}

type firewallReport struct {
	Nft          string `json:"nft"`
	NftTruncated bool   `json:"nft_truncated"`
	Ufw          string `json:"ufw"`
	UfwTruncated bool   `json:"ufw_truncated"`
	Partial      string `json:"partial,omitempty"`
}

func readFirewall() firewallReport {
	ctx, cancel := opBudget()
	defer cancel()
	r := firewallReport{Nft: "absent", Ufw: "absent"}
	if observeHave("nft") {
		out, late := textOf(ctx, "nft", "list", "ruleset")
		r.Nft, r.NftTruncated = capBytes(out, observeTextCap)
		if late {
			r.Nft, r.Partial = "timeout", "nft: timeout"
			return r
		}
	}
	if observeHave("ufw") {
		out, late := textOf(ctx, "ufw", "status", "verbose")
		r.Ufw, r.UfwTruncated = capBytes(out, observeTextCap)
		if late {
			r.Ufw, r.Partial = "timeout", "ufw: timeout"
		}
	}
	return r
}

type unitsReport struct {
	Supported bool         `json:"supported"`
	Reason    string       `json:"reason,omitempty"`
	Partial   string       `json:"partial,omitempty"`
	Failed    []failedUnit `json:"failed"`
	Timers    []timerUnit  `json:"timers"`
}

func readUnits() unitsReport {
	if !observeHave("systemctl") {
		return unitsReport{Reason: "systemctl not installed", Failed: []failedUnit{}, Timers: []timerUnit{}}
	}
	ctx, cancel := opBudget()
	defer cancel()
	r := unitsReport{Supported: true, Timers: []timerUnit{}}
	failed, late := textOf(ctx, "systemctl", "list-units", "--failed", "--no-legend", "--plain")
	r.Failed = parseFailedUnits(failed)
	if late {
		r.Partial = "failed: timeout"
		return r
	}
	timers, late := textOf(ctx, "systemctl", "list-timers", "--all", "--no-legend", "--plain")
	r.Timers = parseTimers(timers)
	if late {
		r.Partial = "timers: timeout"
	}
	return r
}

type dirUsage struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// The filesystem the path lives on and how full THAT is — the question
	// "is the disk under kubelet filling" — read by statfs in microseconds.
	// du over /var/lib/rancher (container images, tens of GB) can run past the
	// op budget, so the directory's own byte count is not attempted here.
	FsPct int `json:"fs_pct"`
}

type diskReport struct {
	Filesystems []diskFS   `json:"filesystems"`
	K8sDirs     []dirUsage `json:"k8s_dirs"`
	Partial     string     `json:"partial,omitempty"`
}

func readDisk() diskReport {
	ctx, cancel := opBudget()
	defer cancel()
	r := diskReport{Filesystems: []diskFS{}, K8sDirs: []dirUsage{}}
	if observeHave("df") {
		out, late := textOf(ctx, "df", "-P")
		r.Filesystems = parseDF(out)
		if late {
			r.Partial = "df: timeout"
		}
	}
	for _, d := range []string{"/var/lib/rancher", "/var/lib/kubelet"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			r.K8sDirs = append(r.K8sDirs, dirUsage{Path: d, Exists: true, FsPct: statfsPct(d)})
		}
	}
	return r
}

type kernelReport struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	Lines     int    `json:"lines"`
	Truncated bool   `json:"truncated"`
	Dmesg     string `json:"dmesg"`
}

func readKernel() kernelReport {
	if !observeHave("dmesg") {
		return kernelReport{Reason: "dmesg not installed"}
	}
	ctx, cancel := opBudget()
	defer cancel()
	out, err := observeExec(ctx, "dmesg", "-T")
	if ctx.Err() != nil {
		return kernelReport{Reason: "dmesg: timeout"}
	}
	if err != nil && len(out) == 0 {
		return kernelReport{Reason: "dmesg: " + err.Error()}
	}
	text, cut := capLines(string(out), 200, observeTextCap)
	n := 0
	if text != "" {
		n = strings.Count(text, "\n") + 1
	}
	return kernelReport{Supported: true, Lines: n, Truncated: cut, Dmesg: text}
}

type k8sReport struct {
	Supported bool      `json:"supported"`
	Reason    string    `json:"reason,omitempty"`
	Nodes     []k8sNode `json:"nodes,omitempty"`
	Pods      *k8sPods  `json:"pods,omitempty"`
}

func readK8s() k8sReport {
	if _, err := os.Stat(observeKubeconfig); err != nil {
		return k8sReport{Reason: "no read-only kubeconfig at " + observeKubeconfig + " (control planes only)"}
	}
	if !observeHave("kubectl") {
		return k8sReport{Reason: "kubectl not installed"}
	}
	ctx, cancel := opBudget()
	defer cancel()
	rawNodes, err := observeExec(ctx, "kubectl", "--kubeconfig", observeKubeconfig, "get", "nodes", "-o", "json")
	if ctx.Err() != nil {
		return k8sReport{Reason: "kubectl get nodes: timeout"}
	}
	if err != nil {
		return k8sReport{Reason: "kubectl get nodes: " + err.Error()}
	}
	nodes, err := parseK8sNodes(rawNodes)
	if err != nil {
		return k8sReport{Reason: "nodes json: " + err.Error()}
	}
	rawPods, err := observeExec(ctx, "kubectl", "--kubeconfig", observeKubeconfig, "get", "pods", "-A", "-o", "json")
	if ctx.Err() != nil {
		return k8sReport{Reason: "kubectl get pods: timeout", Nodes: nodes}
	}
	if err != nil {
		return k8sReport{Reason: "kubectl get pods: " + err.Error(), Nodes: nodes}
	}
	pods, err := parseK8sPods(rawPods)
	if err != nil {
		return k8sReport{Reason: "pods json: " + err.Error(), Nodes: nodes}
	}
	return k8sReport{Supported: true, Nodes: nodes, Pods: &pods}
}
