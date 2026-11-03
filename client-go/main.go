// privatae-bastion — a single static binary that turns this machine into a bastion
// into your Privatae network. No Docker, no Python, no separate WireGuard install.
//
// The tunnel runs in userspace (gVisor netstack) for the forward path, so `run`
// needs no TUN device and no root. You pair with a short token from your host's
// "Set up a bastion" action; the binary generates its OWN keys and pulls only its
// cert + routing from your host. Distributed via npm / a plain binary.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func usage() {
	fmt.Fprintln(os.Stderr, `privatae-bastion — watches the AI agents on this machine, and connects it to a Host if you run one.

Usage:
  privatae-bastion pair <token>   enroll this machine with a token from your host's "Set up a bastion".
                               Each pair ADDS a host — one daemon serves them all; pairing an
                               already-paired host is refused (it would rotate its credentials)
  privatae-bastion pair -      the same, with the token as the first line of standard input,
                               so it is not in the process list or your shell history. Every
                               form of pair below takes - in place of <token> as well
  privatae-bastion pair --replace <token>
                               re-pair an already-paired host: rotates its credentials, keeps
                               its local port, context store, and DCN state
  privatae-bastion pair --redeem-url unix:///run/privatae-host/enroll.sock <token>
                               pair with a Host on THIS machine that has no platform: the
                               token is redeemed over that socket, the lanes go over the
                               lane socket the Host names, and its CA is pinned for life
  privatae-bastion pair --redeem-url https://127.0.0.1:8810/v1/local/redeem --host-ca <pem> <token>
                               pair with a Host that has no platform and runs in a VM on
                               this machine: the token is redeemed over TLS that trusts
                               that CA alone (name host.cseries.internal), the lanes go to
                               the lane port the Host names, and the CA is pinned for life.
                               No coder runs over this pairing
  privatae-bastion pair <pairing code skp_…>
                               the same pairing from the one code a Cloud Host's card gives:
                               it carries the enroll address and the CA's fingerprint, and
                               the CA is taken from the enroll port only under that
                               fingerprint. On a local machine that already serves a Host,
                               it asks here whether to add this one as well. Exit 3: already
                               paired with this Host, nothing changed
  privatae-bastion run            bring up the tunnel + lanes for EVERY paired host
                               (a loopback control port per host for the verbs below:
                               127.0.0.1:7878, then 7879, …)
  privatae-bastion add-folder [--host <host>] <path> [name]
                               add a folder to your network — your files stay here; Privatae
                               Host keeps only the index; you approve on your Host with your code.
                               --host (a host name or unique prefix) is required when more
                               than one host is paired
  privatae-bastion stepup-enroll [--host <host>] [--rotate] [--console-only]
                               enroll a second factor ON THIS MACHINE: from then on your host
                               can only reach a folder or move files here after you approve
                               the request on this machine — the host never handles the code.
                               --console-only: show the secret only on this console and keep
                               it only in the system service's state (an installer's elevated step)
  privatae-bastion tray        Windows, beside the system service: your icon and approvals
                               window, as you; started at every sign-in
  sudo -H privatae-bastion claim-owner <name>
                               state who owns this machine. Root is required because there
                               is no authority above the box to ask. The name travels to every
                               host this machine serves and shows on its card there. Optional,
                               and it grants nothing anywhere
  privatae-bastion unpair <host>  remove a pairing: tears its tunnel down and deletes the pairing
                               (root on a networked bastion). Your context store and DCN
                               state on this machine are left in place
  sudo -H privatae-bastion set-mode <local|networked>
                               local (default): one host, non-root is fine, a second pair is
                               refused. networked: a root-owned service serving several hosts,
                               where every pairing after the anchor waits for the anchor host's
                               approval. install.sh --networked sets it for you
  privatae-bastion service install|uninstall|status
                               macOS and Windows: run this bastion as the system's own
                               service (launchd as root; a Windows service as LocalSystem),
                               so the machine's administrator, not the signed-in user,
                               decides whether it runs. Needs machine authority.
                               install.sh --networked / install.ps1 -Networked do it for you
  sudo -H privatae-bastion claim-anchor [--owner <name>] <token>
                               networked mode: redeem a token from YOUR host and make it the
                               anchor — the one host that approves who else may pair here.
                               Needs root; works on a box with no pairing or one pairing
  sudo -H privatae-bastion claim-anchor --rotate [--owner <name>] <token>
                               move the anchor to a DIFFERENT host. Needs root AND the
                               current anchor's signed consent (anchor.consent.json), or
                               14 days without a heartbeat from it
  sudo -H privatae-bastion release-anchor --host <name> (--host-ca <pem file> | --force)
                               the anchor host is gone (its data deleted): drop the anchor,
                               unpair it and set its DCN state aside, so a new Host can be
                               paired and anchored. Needs machine authority. --host-ca is the
                               NEW Host's CA, refused when it is the one this box pinned (that
                               Host is not gone); --force skips that check, at a terminal only
  privatae-bastion uninstall [--delete-data]
                               remove the service and the program. The state stays (pairings,
                               keys, the audit log) unless --delete-data, confirmed at a terminal.
                               Installed for the whole machine, it needs the administrator
  privatae-bastion approvals-owner --sid <SID> [--replace]    (Windows)
  privatae-bastion approvals-owner --account <name> [--replace]   (Linux, macOS)
                               beside the system service, the one person's account it serves:
                               on Windows the tray's approvals, on Linux and macOS the console
                               (privatae-bastion ui) without sudo. Machine authority; another
                               account needs --replace, at a terminal only
  sudo -H privatae-bastion claim-anchor --repin
                               same host, new name: re-sign anchor.json from the
                               pairing this box already holds, after the host's
                               own address changed. No token. Cannot move the
                               anchor anywhere.
  privatae-bastion approvals [--host <host> | --machine] [--json]
                               show what your host is asking to do on this machine, in plain words
  privatae-bastion approve [--host <host> | --machine] <id>
                               approve one request with a code from the authenticator enrolled here
  privatae-bastion deny [--host <host> | --machine] <id>
                               refuse one request. From the machine's owner account, beside the
                               bastion installed for the whole machine, both act on that bastion,
                               and so do switch (off with nothing, on with the owner's code) and,
                               with nothing, approvals drop, grants drop, ops drop and device-deny
  privatae-bastion approvals drop [--host <host>] <id>
                               take back an approval this machine issued and has not used yet
  privatae-bastion grants drop <store id> [--host <host>]
                               remove a folder grant held on this machine; the host is told
  privatae-bastion device-init    make THIS machine your approval device: from then on a write a
                               host asks of any machine you govern is approved with a tap here
  privatae-bastion device-approvals [--json]   what your machines are asking you to approve, in their words
  privatae-bastion device-approve <id>|all / device-deny <id>
  sudo -H privatae-bastion pin-device <key>
                               on a machine you govern: accept approvals signed by your device
                               (the key device-init printed). unpin-device <key> withdraws it
  privatae-bastion ops [--host <host>] [--json]  the ops your host wrote that this machine holds, and the
                               standing op grants; ops drop <grant> takes one back
  sudo -H privatae-bastion root-exec grant [--host <host>] --for <30d>
                               let the anchor host run commands AS ROOT here, one at a time,
                               with no approval per command, until the time you choose. Asks
                               for the code from the authenticator enrolled here. Every command
                               is recorded here whole
  privatae-bastion root-exec [--host <host>]   the root-command grant held here, if any;
                               root-exec revoke takes it back
  privatae-bastion quarantine clear <host>
                               reopen a host's write lanes this machine closed after repeated
                               refusals (5 in 10 minutes)
  privatae-bastion quarantine clear --asker <account>
                               let agents running as that account ask this machine again, after
                               5 of their asks were refused in 10 minutes
  sudo -H privatae-bastion switch <host> <family> on|off
                               switch one capability family off for a host on this machine,
                               or clear that refusal (the console page's switch). Off only
                               removes reach; on grants nothing past the host's signed grant
  privatae-bastion switch --list [--json]
                               every paired host's families, on or off, one per line
  privatae-bastion agents [--json] [--prompts]
                               every AI agent on this machine and what it is doing: its
                               session name and title, whether it waits for you, its folder
                               and branch, what it is running now (--prompts: its last prompt)
  privatae-bastion agents show <pid or session> [--json] [--prompts]
                               one agent with everything known about it: what it is, the file
                               it runs, how it was recognised, what it says about itself
  privatae-bastion doctor [--json]
                               what is wrong with this install, and the fix for each one.
                               Exit 1 when something is
  privatae-bastion report [--since 7d] [--json] [--out FILE | --out -]
                               write what this bastion knows as one Markdown file: agents,
                               scheduled agents, MCP tool-server problems, the baseline, activity.
                               --out - prints it
  privatae-bastion schedules [--json]
                               scheduled jobs that start an AI agent with nobody at the keyboard
  privatae-bastion tool-servers [--json]
                               the MCP tool servers configured here and what is wrong with each
  privatae-bastion posture [--json]
                               Linux: firewall, SSH, fail2ban, security updates, disk, load
  privatae-bastion activity [--since 7d] [--json]
                               what happened on this machine, newest first: stops, your
                               approvals, what each Host did, and changes made here
  privatae-bastion stop <pid or session> [--wait 5m] [--json]
                               stop an agent this bastion sees, and every process it started,
                               with your code as the machine's owner (stepup-enroll --machine).
                               Run by an agent, it only asks: you approve under Waiting for you
                               in the console. --wait follows the ask until it is answered
  privatae-bastion request <id> [--wait 5m] [--json]
                               where an ask stands: waiting, approved, stopped, not stopped or
                               denied. Exit 0 stopped (or asked), 1 not, 3 still waiting
                               From the machine's owner account, beside the bastion installed for
                               the whole machine, the reads (status, agents, schedules,
                               tool-servers, posture, baseline, activity, report, approvals,
                               switch --list, ops, device-approvals, backup key show,
                               backup requests, backup shares, doctor) ask that bastion and
                               show the whole machine
  privatae-bastion help        this text
  privatae-bastion coders set [--max N] [--mem MB] [--cpus F] [--engines a,b|all] [--allow-lan h[:p],...]
                          [--image-prefix <registry/path/>|default]
  privatae-bastion coders on | off | drop [--host H] | status [--json]
                               let your hosts run sealed coding runs on this machine (Linux, as
                               root): how many at once, how big each is, which engines. Off by
                               default; each run has no network but a proxy to the internet
  privatae-bastion git-setup      print the git config lines that route git.privatae.ai
                               through this bastion and your host
  privatae-bastion git-credential git's credential helper — fetches your forge token from your
                               host on every git auth (git-setup resets the helper chain so no
                               other helper caches it)
  privatae-bastion ui             open the local UI in your browser — what this machine is
                               doing, on this machine. Served by the running bastion on
                               127.0.0.1 and reachable from nowhere else
  privatae-bastion context        choose what your files become on your network. Runs as
                               you, so it shows exactly what you can already open, and asks
                               your host before anything is added
  privatae-bastion status [--json]   show every pairing + tunnel status
  privatae-bastion baseline record [--force]
                               record what is NORMAL on this machine: every automated
                               program, its user and a digest of the file it runs from.
                               Administrator only. --force replaces an existing baseline
                               (also: observe:baseline)
  privatae-bastion baseline [show] [--json]
                               print the baseline this machine holds (also: observe:baseline:show)
  privatae-bastion baseline diff [--json]
                               what is running here that the baseline does not hold:
                               new programs, replaced binaries, new standing jobs, with
                               the ordinary ones filtered out. Administrator only.
                               --json for the full record including what was filtered
                               (also: observe:delta)
  privatae-bastion observe        print what this machine would report about agents, automations
                               and scheduled jobs on its next check-in (read-only, JSON)
  privatae-bastion backup key init | key show | reseal | requests | approve | deny |
                          restore-plan | share | shares | unshare
                               backups: make this bastion's backup key, and hand one
                               backup's key to a host that restores it, when you approve.
                               `+"`privatae-bastion backup`"+` lists the forms
  privatae-bastion version

Your host reaches this machine only through lanes this bastion opens and gates
itself. Nothing on this machine drives the host: there is no MCP endpoint here.`)
}

// takeHostFlag pulls `--host <name>` out of an argument list wherever it
// sits, so `approvals drop --host X <id>` and `grants drop <id> --host X` both
// work — on a machine serving several hosts (most of the fleet) the flag is
// not optional, and a parser that only saw it in one position refused the
// command on exactly those machines.
func takeHostFlag(args []string) (string, []string) {
	host := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--host" && i+1 < len(args) {
			host = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return host, rest
}

const pairUsage = "usage: privatae-bastion pair [--replace] [--redeem-url unix:///<socket> | --redeem-url https://<host>:<port>/<path> --host-ca <pem file>] <token> | -\n" +
	"       privatae-bastion pair <pairing code skp_…> | -\n" +
	"       privatae-bastion pair --open [--port 8812]   (on a server: your Host connects to it with the code this shows)\n" +
	"  - reads the token or pairing code from standard input, so it stays out of the process list and shell history\n" +
	"  exit status: 0 paired, 3 already paired with this Host (nothing changed), anything else a failure"

// parsePairArgs reads `pair`'s flags in any order: --replace, --redeem-url
// for a Host with no platform (pair_unix.go, pair_tcp.go) and --host-ca for
// an https:// one. At most one token: "" when none was given, which pairToken
// (pair_stdin.go) refuses with the usage; `-` reads it from standard input.
func parsePairArgs(args []string) (token, redeemURL, hostCA string, replace bool, err error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--replace":
			replace = true
		case args[i] == "--redeem-url" && i+1 < len(args):
			redeemURL = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--redeem-url="):
			redeemURL = strings.TrimPrefix(args[i], "--redeem-url=")
		case args[i] == "--host-ca" && i+1 < len(args):
			hostCA = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--host-ca="):
			hostCA = strings.TrimPrefix(args[i], "--host-ca=")
		case strings.HasPrefix(args[i], "--"):
			return "", "", "", false, fmt.Errorf("unknown flag %s\n%s", args[i], pairUsage)
		default:
			rest = append(rest, args[i])
		}
	}
	switch len(rest) {
	case 0:
		return "", redeemURL, hostCA, replace, nil
	case 1:
		return rest[0], redeemURL, hostCA, replace, nil
	}
	return "", "", "", false, errors.New(pairUsage)
}

func main() {
	// Started by the Windows Service Control Manager: the service runs `run`
	// itself and never reaches the argument parsing below.
	if maybeRunAsWindowsService() {
		auditFlush(auditFlushOnExit)
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// Before ANY command reads state: on a machine whose bastion is a system
	// service, an administrator's command acts on the service's state, and an
	// ordinary account's pair/run/status is refused (sysservice.go).
	adoptSystemServiceState()
	if err := guardServiceFork(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "service":
		err = cmdService(os.Args[2:])
	case "pair":
		// pair --open: a pairing window for a Host that connects to this
		// server (pair_window.go).
		if addr, open, oerr := parsePairOpenArgs(os.Args[2:]); open {
			if oerr != nil {
				fmt.Fprintln(os.Stderr, oerr)
				os.Exit(2)
			}
			err = cmdPairOpen(addr, os.Stdout)
			break
		}
		token, redeemURL, hostCA, replace, perr := parsePairArgs(os.Args[2:])
		if perr == nil {
			token, perr = pairToken(token, os.Stdin, stdinIsConsole(), os.Stderr)
		}
		if perr != nil {
			fmt.Fprintln(os.Stderr, perr)
			os.Exit(2)
		}
		err = cmdPair(token, redeemURL, hostCA, replace)
		// Already paired with this Host, nothing changed: its own exit status,
		// so the installers (install.ps1 -Pair, install.sh with
		// PRIVATAE_PAIR_CODE) report "already connected".
		var already *alreadyPairedError
		if errors.As(err, &already) {
			auditFlush(auditFlushOnExit)
			fmt.Fprintln(os.Stderr, already)
			os.Exit(pairExitAlreadyPaired)
		}
	case "run":
		err = cmdRun()
	case "observe:baseline":
		// The accounting of what is NORMAL here (baseline.go). Root,
		// and --force is required to replace an existing one: retaking a
		// baseline silently absorbs whatever has appeared since, which is the
		// one way this feature can be turned off by accident.
		args := os.Args[2:]
		err = cmdObserveBaseline(len(args) > 0 && args[0] == "--force")
	case "observe:baseline:show":
		err = cmdObserveBaselineShow()
	case "observe:delta":
		// What is running here that the accounting does not hold (delta.go).
		// Administrator only, for the same reason the accounting
		// is: a pass that cannot read what the baseline read reports the
		// difference between two ACCOUNTS rather than a change to the machine.
		args := os.Args[2:]
		err = cmdObserveDelta(len(args) > 0 && args[0] == "--json")
	case "observe":
		// What this box would report on its next heartbeat about agents, automations and
		// scheduled jobs — the gate for the detection plane, and the operator's own eyes.
		// Read-only; prints the same JSON the host receives, nothing else.
		err = cmdObserve()
	case "lab-selftest":
		// Lab box operator tooling: run mode=lab from a spec file without the host relay.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion lab-selftest <spec.json>")
			os.Exit(2)
		}
		err = cmdLabSelftest(os.Args[2])
	case "add-folder":
		args := os.Args[2:]
		host := ""
		if len(args) >= 2 && args[0] == "--host" {
			host = args[1]
			args = args[2:]
		}
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion add-folder [--host <host>] <path> [display name]")
			os.Exit(2)
		}
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		err = cmdAddFolder(host, args[0], name)
	case "git-credential":
		// git calls: `privatae-bastion git-credential [--host h] <get|store|erase>`
		args := os.Args[2:]
		host := ""
		if len(args) >= 2 && args[0] == "--host" {
			host = args[1]
			args = args[2:]
		}
		action := "get"
		if len(args) > 0 {
			action = args[0]
		}
		err = cmdGitCredential(host, action)
	case "backup":
		// The person's own backups (backupcli.go): their key, opening a
		// backup, and resealing one backup's key to a host that restores it.
		err = cmdBackup(os.Args[2:])
	case "stepup-enroll":
		args := os.Args[2:]
		host, machine, rotate, consoleOnly := "", false, false, false
		for len(args) > 0 {
			switch {
			case args[0] == "--host" && len(args) >= 2:
				host = args[1]
				args = args[2:]
			case args[0] == "--machine":
				machine = true
				args = args[1:]
			case args[0] == "--rotate":
				rotate = true
				args = args[1:]
			case args[0] == "--console-only":
				consoleOnly = true
				args = args[1:]
			default:
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion stepup-enroll [--host <host> | --machine] [--rotate] [--console-only]")
				os.Exit(2)
			}
		}
		err = cmdStepupEnroll(host, machine, rotate, consoleOnly)
	case "approvals", "approve", "deny":
		// The user confirms (or refuses) what their host asked for, ON this machine,
		// with the factor enrolled here. The host never handles the code.
		host, args := takeHostFlag(os.Args[2:])
		machine, args := takeMachineFlag(args)
		switch os.Args[1] {
		case "approvals":
			// approvals drop <id>: revoke an approval this box issued and has
			// not yet burned — the console can always take back what it gave.
			if len(args) >= 2 && args[0] == "drop" {
				err = cmdStepupDrop(host, machine, args[1])
				break
			}
			asJSON, jerr := jsonOnly("usage: privatae-bastion approvals [--host <host> | --machine] [--json]", args)
			if jerr != nil {
				fmt.Fprintln(os.Stderr, jerr)
				os.Exit(2)
			}
			err = cmdStepupApprovals(host, machine, asJSON)
		case "approve":
			if len(args) < 1 {
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion approve [--host <host> | --machine] <request id>")
				os.Exit(2)
			}
			err = cmdStepupApprove(host, machine, args[0])
		case "deny":
			if len(args) < 1 {
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion deny [--host <host> | --machine] <request id>")
				os.Exit(2)
			}
			err = cmdStepupDeny(host, machine, args[0])
		}
	case "release-anchor":
		// An anchor whose Host is gone (anchor_release.go): machine authority
		// only, the host named, and the new Host's CA to prove it is gone.
		host, args := takeHostFlag(os.Args[2:])
		caFile, force := "", false
		for len(args) > 0 {
			switch {
			case args[0] == "--host-ca" && len(args) >= 2:
				caFile = args[1]
				args = args[2:]
			case args[0] == "--force":
				force = true
				args = args[1:]
			default:
				host = ""
				args = nil
			}
		}
		if host == "" {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion release-anchor --host <the anchor host> (--host-ca <the new Host's CA> | --force)   (from an Administrator terminal / with sudo -H)")
			os.Exit(2)
		}
		err = cmdReleaseAnchor(host, caFile, force)
	case "approvals-owner":
		// The one account the tray's lane serves (approvals_owner.go).
		// On Linux and macOS, the account the console lane serves
		// (owner_account.go): --account.
		args := os.Args[2:]
		sid, account, replace, bad := "", "", false, false
		for len(args) > 0 {
			switch {
			case args[0] == "--sid" && len(args) >= 2:
				sid = args[1]
				args = args[2:]
			case args[0] == "--account" && len(args) >= 2:
				account = args[1]
				args = args[2:]
			case args[0] == "--replace":
				replace = true
				args = args[1:]
			default:
				bad = true
				args = nil
			}
		}
		windows := runtime.GOOS == "windows"
		if bad || (windows && (sid == "" || account != "")) || (!windows && (account == "" || sid != "")) {
			if windows {
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion approvals-owner --sid <account SID> [--replace]   (from an Administrator terminal)")
			} else {
				fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion approvals-owner --account <name> [--replace]")
			}
			os.Exit(2)
		}
		if windows {
			err = cmdApprovalsOwner(sid, replace)
		} else {
			err = cmdOwnerAccount(account, replace)
		}
	case "tray":
		// The signed-in person's icon beside a system service
		// (tray_pipe_windows.go), started at every sign-in.
		err = cmdTray()
	case "unpair":
		// Remove one pairing: file + grant file; context store and DCN state
		// stay (user data). Root on a networked box, any user on a local one.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion unpair <host>")
			os.Exit(2)
		}
		err = cmdUnpair(os.Args[2])
	case "set-mode":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion set-mode <local|networked>")
			os.Exit(2)
		}
		err = cmdSetMode(os.Args[2])
	case "claim-anchor":
		// Anchoring (anchor.go): root binds this machine to ONE host, which from
		// then on approves every further pairing here.
		//
		// The token is OPTIONAL and usually unwanted. A box you have already
		// paired holds the answer to "which host" already, so the ordinary flow
		// is `pair <token>` → `set-mode networked` → `claim-anchor`, with no
		// second token to fetch. On a box serving SEVERAL hosts — which is what
		// networked mode is FOR — `--host <name>` says which of them holds the
		// anchor; that is a choice among pairings the box already has, not a
		// credential. A token is needed only to name a host this box does not
		// serve at all: a fresh unpaired box, or --rotate.
		args := os.Args[2:]
		rotate, repin, owner, host := false, false, "", ""
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			switch {
			case args[0] == "--rotate":
				rotate = true
				args = args[1:]
			case args[0] == "--repin":
				repin = true
				args = args[1:]
			case args[0] == "--owner" && len(args) >= 2:
				owner = args[1]
				args = args[2:]
			case args[0] == "--host" && len(args) >= 2:
				host = args[1]
				args = args[2:]
			default:
				fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion claim-anchor [--host <name>] [--rotate|--repin] [--owner <name>] [token]\n"+
					"  no token:      anchor to the host this box is already paired to (the usual case)\n"+
					"  --host <name>: which pairing holds the anchor, when this box serves several\n"+
					"  token:         name a host this box does not serve yet — a fresh box, or --rotate")
				os.Exit(2)
			}
		}
		// --repin takes NO token: the new name comes from the pairing this box
		// already holds, so there is nothing to redeem and nothing to type.
		if repin {
			// --owner is refused rather than ignored: --repin deliberately keeps
			// the existing owner (it is the same host under a new name), so a
			// caller passing one is asking for something this command does not do.
			if rotate || owner != "" || host != "" || len(args) > 0 {
				fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion claim-anchor --repin   (no token, no --owner, not with --rotate)")
				os.Exit(2)
			}
			err = cmdRepinAnchor()
			break
		}
		if len(args) > 1 {
			fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion claim-anchor [--host <name>] [--rotate|--repin] [--owner <name>] [token]\n"+
				"  no token:      anchor to the host this box is already paired to (the usual case)\n"+
				"  --host <name>: which pairing holds the anchor, when this box serves several\n"+
				"  token:         name a host this box does not serve yet — a fresh box, or --rotate")
			os.Exit(2)
		}
		// No token is the ordinary case: cmdClaimAnchor reads "" as "use the
		// pairing this box already holds", and refuses if that is ambiguous.
		err = cmdClaimAnchor(strings.Join(args, ""), rotate, owner, host)
	case "claim-owner":
		// Machine ownership: root on this box signs an owner claim that travels
		// on every pairing's heartbeat. Optional, and it grants nothing.
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion claim-owner <name>")
			os.Exit(2)
		}
		err = cmdClaimOwner(strings.Join(os.Args[2:], " "))
	case "git-setup":
		err = cmdGitSetup()
	case "context":
		// YOUR files, in a process running as YOU (contextui.go). Unlike `ui` this
		// starts a server of its own and stays in the foreground: it is not a
		// view of the daemon, it is a separate surface with a different owner.
		err = cmdContextUI()
	case "uninstall":
		// Removes the service and the program; keeps the state and the audit
		// log unless --delete-data (uninstall.go).
		del := false
		for _, a := range os.Args[2:] {
			if a != "--delete-data" {
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion uninstall [--delete-data]")
				os.Exit(2)
			}
			del = true
		}
		err = cmdUninstall(del)
	case "ui":
		// Opens a browser at the RUNNING daemon's UI (ui.go). It starts no
		// server of its own: the UI belongs to the process that knows what is
		// live, and a second one would render a machine nobody is serving.
		err = cmdUI()
	case "status":
		err = cmdStatus(os.Args[2:])
	// ── the approval device (device.go) and the write gate's console side ──
	case "device-init":
		err = cmdDeviceInit()
	case "device-approvals":
		err = cmdDeviceApprovals(os.Args[2:])
	case "device-approve", "device-deny":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion "+os.Args[1]+" <request id> [--code <code>]")
			os.Exit(2)
		}
		if os.Args[1] == "device-approve" {
			code := ""
			if len(os.Args) >= 5 && os.Args[3] == "--code" {
				code = os.Args[4]
			}
			err = cmdDeviceApproveCode(os.Args[2], code)
		} else {
			err = cmdDeviceDeny(os.Args[2])
		}
	case "pin-machine", "unpin-machine":
		// On the approval device: pin (or drop) a machine's key, as that
		// machine printed it when this device was pinned there.
		if (os.Args[1] == "pin-machine" && len(os.Args) < 4) || len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion pin-machine <hostname> <key>   |   unpin-machine <hostname>")
			os.Exit(2)
		}
		key := ""
		if len(os.Args) >= 4 {
			key = os.Args[3]
		}
		err = cmdPinMachine(os.Args[2], key, os.Args[1] == "unpin-machine")
	case "pin-device", "unpin-device":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: sudo -H privatae-bastion "+os.Args[1]+" <device key>")
			os.Exit(2)
		}
		err = cmdPinDevice(os.Args[2], os.Args[1] == "unpin-device")
	case "grants":
		// grants drop <store id> [--host <host>]: the person at the machine
		// removes a held store grant here (localdeny.go's doctrine: the
		// console can only ever remove reach). The host learns on the next
		// beat that the store is gone.
		host, args := takeHostFlag(os.Args[2:])
		if len(args) < 2 || args[0] != "drop" {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion grants drop <store id> [--host <host>]")
			os.Exit(2)
		}
		err = cmdGrantsDrop(host, args[1])
	case opSandboxSubcommand:
		// The sandbox child (ops_exec_linux.go): never typed by a person; the
		// daemon re-execs itself this way inside fresh namespaces.
		if len(os.Args) < 3 {
			os.Exit(125)
		}
		os.Exit(opSandboxChildMain(os.Args[2]))
	case opSandboxScopeSubcommand:
		// A root op's scope (ops_taskcap_linux.go): never typed by a person;
		// systemd-run starts it for the daemon.
		if len(os.Args) < 3 {
			os.Exit(125)
		}
		os.Exit(opSandboxScopeMain(os.Args[2]))
	case opActionSubcommand, opActionChildSubcommand, opActionProbeSubcommand:
		// An action op's unit and its sandbox's pid 1 (ops_action_linux.go):
		// never typed by a person; the daemon starts them.
		if len(os.Args) < 3 {
			os.Exit(125)
		}
		if os.Args[1] == opActionSubcommand {
			os.Exit(opActionOuterMain(os.Args[2]))
		}
		if os.Args[1] == opActionProbeSubcommand {
			os.Exit(opActionProbeMain(os.Args[2]))
		}
		os.Exit(opActionChildMain(os.Args[2]))
	case "ops":
		// ops [--host <host>] [--json]   what ops and op grants this machine holds
		// ops drop <grant> [--host <host>]  take back a held op grant (the host is told)
		// ops drop --all [--host <host>]    take back every op grant the host holds here
		host, args := takeHostFlag(os.Args[2:])
		if len(args) >= 2 && args[0] == "drop" {
			err = cmdOpsDrop(host, args[1])
			break
		}
		asJSON, jerr := jsonOnly("usage: privatae-bastion ops [--host <host>] [--json]   |   ops drop <grant>|--all [--host <host>]", args)
		if jerr != nil {
			fmt.Fprintln(os.Stderr, jerr)
			os.Exit(2)
		}
		err = cmdOpsList(host, asJSON)
	case "root-exec":
		// root-exec [--host <host>] [grant --for <d> | revoke] (rootexec.go): the
		// standing grant for the anchor host's root commands, given and taken
		// back only here.
		err = cmdRootExec(os.Args[2:])
	case "quarantine":
		// quarantine clear <host>: lift the box's own hold on a pairing's
		// write lanes (quarantine.go) — the person at the machine, only.
		// quarantine clear --asker <account>: the same for an account whose
		// agents' asks were held (askquarantine.go).
		if len(os.Args) < 4 || os.Args[2] != "clear" {
			fmt.Fprintln(os.Stderr, "usage: privatae-bastion quarantine clear <host> | --asker <account>")
			os.Exit(2)
		}
		if os.Args[3] == "--asker" {
			if len(os.Args) != 5 {
				fmt.Fprintln(os.Stderr, "usage: privatae-bastion quarantine clear --asker <account>")
				os.Exit(2)
			}
			err = cmdQuarantineClearAsker(os.Args[4])
			break
		}
		err = cmdQuarantineClear(os.Args[3])
	case "coders":
		// coders set|on|off|drop|status (coders_cli.go): size this machine
		// for coder runs. Off by default.
		err = cmdCoders(os.Args[2:])
	case "report":
		// report [--since 7d] [--json] [--out FILE] (report.go).
		err = cmdReport(os.Args[2:])
	case "activity":
		// activity [--since 7d] [--json] (activity.go): what happened here.
		err = cmdActivity(os.Args[2:])
	case "agents":
		// agents [--json] [--prompts] (agents_cli.go): every agent here and
		// what it is doing — its session, folder, branch, what it runs now.
		err = cmdAgents(os.Args[2:])
	case "stop":
		// stop <pid> [--wait D] [--json] (stop_local.go): the machine's owner
		// stops an agent, with their own second factor; run by an agent it
		// only files the request.
		err = cmdStop(os.Args[2:])
	case "request":
		// request <id> [--wait D] [--json] (askstatus.go): where an ask stands.
		err = cmdRequest(os.Args[2:])
	case "schedules":
		// schedules [--json] (machine_cli.go): scheduled jobs that start an agent.
		err = cmdSchedules(os.Args[2:])
	case "tool-servers":
		// tool-servers [--json] (machine_cli.go): MCP tool servers and their problems.
		err = cmdToolServers(os.Args[2:])
	case "posture":
		// posture [--json] (machine_cli.go): the checks a Host runs on its servers.
		err = cmdPosture(os.Args[2:])
	case "baseline":
		// baseline show|diff [--json], baseline record [--force]
		// (machine_cli.go): observe:baseline* under the words people use.
		err = cmdBaseline(os.Args[2:])
	case "doctor":
		// doctor [--json] (doctor.go): what is wrong with this install, and
		// the fix for each one.
		err = cmdDoctor(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	case "switch":
		// switch <host> <family> on|off, switch --list (switch_cli.go): the
		// local switch without the console page, for a machine nobody sits at.
		err = cmdSwitch(os.Args[2:])
	case "version", "-v", "--version":
		// clientVersion (run.go) is the load-bearing string: publish.sh stamps it via
		// -ldflags, the heartbeat reports it, and self-update compares against it. The
		// old separate `version` var was never stamped (publish stamps clientVersion),
		// so `version` printed a stale hardcoded default — dropped.
		fmt.Println("privatae-bastion", clientVersion)
	default:
		usage()
		os.Exit(2)
	}
	// The command's audit rows reach the system log before the process ends
	// (auditlog.go queues them off the op's own path).
	auditFlush(auditFlushOnExit)
	var quiet quietExit
	if errors.As(err, &quiet) {
		os.Exit(quiet.code) // the command already said what happened
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
