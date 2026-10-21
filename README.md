# privatae-bastion

[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](client-go/go.mod)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#supported-platforms)
[![ci](https://git.privatae.ai/privatae/privatae-bastion/actions/workflows/ci.yml/badge.svg?branch=main)](https://git.privatae.ai/privatae/privatae-bastion/actions)

**One static Go binary that turns your own machine into a bastion in your Privatae network.**

No Docker, no Python, no database, no separate WireGuard install. You pair the
binary with a short token from your host, and from then on your host can reach
this machine only through the tunnel this bastion dials out and the lanes it
gates. Your files stay where they are. Nothing on this machine drives the host:
there is no MCP endpoint here.

The published release is whatever `privatae.ai/bastion/version.json` names.
`deploy/VERSION` on `main` is the next release, which may not be published
yet. From 0.42.0 on, every release manifest is signed and every published
binary can be rebuilt from this source and compared
([Verify a release](#verify-a-release)). See [CHANGELOG.md](CHANGELOG.md).

```sh
# macOS / Linux (a home machine, running as you)
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
privatae-bastion pair <token>        # token from your host's "Set up a bastion"
privatae-bastion run                 # tunnel + lanes up
privatae-bastion add-folder ~/docs   # hand a folder to your network; you approve on your host
```

```powershell
# Windows
irm https://privatae.ai/bastion/install.ps1 | iex
privatae-bastion pair <token>
privatae-bastion run
```

On a Linux server installed as root, the installer also enables a service that
runs the daemon for you, so it is `sudo -H privatae-bastion pair <token>` and
nothing else. See [Install](#install).

---

## Contents

- [Why a bastion](#why-a-bastion)
- [Install](#install)
- [Quick start](#quick-start)
- [Local and networked modes](#local-and-networked-modes)
- [A Host on this machine](#a-host-on-this-machine)
- [What the bastion does](#what-the-bastion-does)
- [Command reference](#command-reference)
- [Security model](#security-model)
- [Supported platforms](#supported-platforms)
- [Build from source](#build-from-source)
- [Repository layout](#repository-layout)
- [Contributing](#contributing)
- [License](#license)

---

## Why a bastion

A Privatae host is an AI that works for you. To be useful it needs to see your
files, use your machine's models, and sometimes act on the machine. The bastion
is the piece that makes that possible **without handing the host your machine**.

The bastion dials your host; your host never dials your machine. No port is
opened on any externally reachable interface (the control ports and the local
console bind loopback only; the optional memory-mirror forwarder also binds
the replica container's private gateway address). The only thing your host can reach is the
inside of the tunnel this binary brought up, and what it may do there arrives
as a signed grant that this binary verifies locally. Once you enrol a second
factor on this machine, anything that would move your files, download a model,
or open a root shell waits for you to approve it **here**, with a code the host
never sees.

The result: the host gets a precise, auditable view of what you chose to share,
and you keep the keys. [SECURITY.md](SECURITY.md) says what you still have to
trust, and why.

## Install

The installer downloads the binary for your OS and architecture, verifies its
SHA-256 against the release manifest, and only then moves it into place. A
failed check installs nothing.

**macOS / Linux**

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
```

On Linux, running the installer as root also installs an always-on `systemd`
service (`privatae-bastion.service`), so a server is onboarded in two commands:
install, then `sudo -H privatae-bastion pair <token>`.

**Windows (PowerShell)**

```powershell
irm https://privatae.ai/bastion/install.ps1 | iex
```

**Networked bastion** (a shared machine serving several hosts, see
[modes](#local-and-networked-modes)):

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh -s -- --networked
```

```powershell
& ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Networked
```

A networked install runs as the operating system's own service, so it runs
whoever is signed in, and only the machine's administrator can stop it:

- **Linux:** the `systemd` unit above, as root.
- **macOS:** a `launchd` daemon (`ai.privatae.bastion`) running as root. The
  program goes in `/Library/Application Support/privatae/bin`, which only root
  can change, with a link on `PATH`.
- **Windows:** the service `PrivataeBastion`, running as LocalSystem. The
  program goes in `Program Files\Privatae`, which only administrators can
  change. The installer needs an elevated terminal, and removes the logon task
  an earlier install registered. The agent that serves a shared folder runs
  as the folder's owner, under their own token, while they are signed in to
  the machine; it never runs as LocalSystem, and the bastion writes nothing
  into the folder.

On macOS and Windows, `privatae-bastion service install|uninstall|status` does
the same by hand. An administrator's commands (`sudo -H …` on macOS, an
Administrator terminal on Windows) act on the service's state. From an account
that does not administer the machine, `pair`, `run` and `status` are refused,
so that account does not end up with a second, empty bastion of its own.

Release binaries are served from `https://dl.privatae.ai`. The release manifest
(`version.json`, read by the installers at `https://dl.privatae.ai/version.json`
and by the self-updater at `https://privatae.ai/bastion/version.json`) lists the
current version, the commit it was built from, and the URL plus SHA-256 of
every binary. Beside it, `version.json.<first 16 hex of its sha256>.sig` is an
ed25519 signature over a statement naming the release, its version and the
manifest's sha256, made on the key holder's own computer with
`deploy/release-sign`.

## Quick start

1. In your Privatae host, choose **Set up a bastion**. It gives you a one-time
   pairing token.
2. Pair this machine. The binary generates its own keys locally and pulls only
   its certificate and routing from the host.

   ```sh
   privatae-bastion pair <token>
   ```

3. Bring the tunnel and lanes up.

   ```sh
   privatae-bastion run
   ```

   Each paired host gets its own loopback control port, starting at
   `127.0.0.1:7878`. One daemon serves every host you pair.

4. Check on it, or open the local console.

   ```sh
   privatae-bastion status
   privatae-bastion ui
   ```

5. Enrol a second factor on this machine. Until you do, folder grants and
   file moves are gated by the signed grant alone (the host verifies its own
   factor), and model downloads and root shells are refused outright. After
   you do, every one of those waits for your approval here.

   ```sh
   privatae-bastion stepup-enroll
   ```

6. Share a folder. Your files stay on this machine. The host keeps only an
   index, and you confirm the share on the host with your code.

   ```sh
   privatae-bastion add-folder ~/projects/notes "Notes"
   ```

## Local and networked modes

| | **local** (default) | **networked** |
|---|---|---|
| Who it serves | one host | several hosts on one shared machine |
| Runs as | your user is fine | the system's service: root under systemd or launchd, LocalSystem on Windows |
| Second pairing | refused | waits for the **anchor** host's approval |
| Set with | nothing to do | `install.sh --networked` or `sudo -H privatae-bastion set-mode networked` |

In networked mode one host is the **anchor**: the one host that approves every
later pairing on this machine. Claiming the anchor requires root, because there
is no authority above the box to ask. The ordinary flow is `pair`, then
`set-mode networked`, then `claim-anchor` with no token: it is a choice among
pairings the box already holds. A token is needed only to name a host this box
does not serve yet (a fresh machine, or `--rotate`). The anchor can be moved to
another host only with the current anchor's signed consent, or after 14 days of
silence from it.

```sh
sudo -H privatae-bastion claim-anchor [--owner <name>] [--host <host>]   # anchor to a host already paired here
sudo -H privatae-bastion claim-anchor [--owner <name>] <token>           # anchor a fresh machine to your host
sudo -H privatae-bastion claim-anchor --rotate <token>                   # move the anchor to a different host
sudo -H privatae-bastion claim-anchor --repin                            # same host, new address
sudo -H privatae-bastion claim-owner <name>                              # state who owns the machine
```

`claim-owner` is optional. The name shows on this machine's card in every host
it serves, and it grants nothing anywhere.

## A Host on this machine

A Host with no platform (a customer's own server with the Host on it) pairs
with a bastion on the same machine, so its threads can build and test code in
sealed coder runs. Nothing about the walls changes: mutual TLS and the bearer
on every lane, a CA this bastion pins, grants the Host signs and this bastion
verifies on every operation, an anchored machine. What changes is who issues
the certificates (the Host's own CA) and how the two talk: unix sockets in a
directory both reach, `/run/privatae-host/` (root, group `privatae-host`,
1770: the Host runs without privileges and makes its two sockets there, and the
sticky bit keeps it from moving what root made; `runs/` inside it is 0750 root,
so only this bastion makes run sockets), instead of WireGuard through the relay.

| socket | served by | what |
|---|---|---|
| `/run/privatae-host/enroll.sock` | the Host | `pair` redeems its token here (`POST /bastion/enroll/redeem`, the platform redeem's body) |
| `/run/privatae-host/lane.sock` | the Host | every lane, as over the tunnel to `:8443` |
| `/run/privatae-host/runs/<run_id>.sock` | this bastion | one coder run's control plane, for the owning pairing only |

The commands an install script runs on such a machine, as root:

```sh
# 1. The bastion as the machine's service, in networked mode.
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh -s -- --networked
# 2. Pair with the Host over its enroll socket (the token comes from the Host).
sudo -H privatae-bastion pair --redeem-url unix:///run/privatae-host/enroll.sock <token>
# 3. Make the Host the anchor: from now on every coder run-up needs the
#    standing coder grant the Host signs.
sudo -H privatae-bastion claim-anchor --owner <name>
# 4. A way to approve at this machine: it is its own approval device.
privatae-bastion device-init                       # prints the pin-device line
sudo -H privatae-bastion pin-device <key it printed>
# 5. Coder runs of the workspace engine, from images built on this machine.
sudo -H privatae-bastion coders set --engines workspace --image-prefix localhost/privatae-harness/
sudo -H privatae-bastion coders on
sudo systemctl restart privatae-bastion
```

**The one thing the owner does by hand:** approve the Host's coder grant, once,
on this machine's console (`privatae-bastion ui`, then Approvals). Until then
every run-up is refused at the gate.

A `unix://` redeem URL names an absolute socket path and nothing else: a
host, a port or a relative path is refused before the token is read. The
Host's answer names its CA, the lane socket and the runs directory, and both
must be inside the directory of the enroll socket you named. The CA is pinned
as the platform's is: it is the only root the lanes trust, the Host's lane
certificate must carry the pairing's name, and a `pair --replace` that brings a
different CA is refused.

The image is built on the machine and tagged
`<prefix>harness-workspace:<tag>`; the Host names it
`<prefix>harness-workspace@<image ID>`, the ID from
`docker image inspect --format '{{.Id}}'`. Run-up takes an image that is
present that way without a pull or any registry credential. Docker's classic
image store keeps no repo digest for an image built or loaded locally, so
there the run starts from the image ID, and only when the image with that ID
carries a tag of the named repository.

### A Host in a VM on this machine

A Host with no platform that runs in a VM on this machine shares no kernel and
no directory with it. Its installer forwards two ports of the VM to this
machine's loopback and hands over a pairing token with the Host's CA:

```sh
privatae-bastion pair --redeem-url https://127.0.0.1:8810/v1/local/redeem --host-ca host-ca.pem <token>
privatae-bastion run
```

| port | what |
|---|---|
| `8810` | `pair` redeems its token here (`POST /v1/local/redeem`, the platform redeem's body) |
| `8811` | every lane, as over the tunnel to `:8443` |

The redeem and every lane go over TLS that trusts the `--host-ca` alone (no
system roots) and checks the name `host.cseries.internal` on the Host's
certificate; the lanes present this bastion's operator certificate, which the
Host knows it by. The Host's answer must carry that same CA and name a lane on
the host the redeem URL names. The CA is pinned for the pairing's life, as for
a unix pairing. `--host-ca` goes with an `https://` redeem URL only, and both
are checked before the token is read.

Such a pairing has no WireGuard forwards (inference, PII, service slots) and
no coder runs: a run's control plane is a tunnel port or a socket in a unix
pairing's runs directory, and a TCP pairing has neither, so its run-up is
refused before any container starts.

## What the bastion does

Everything below is in `client-go/` and compiled into the one binary.

### Tunnel
A userspace WireGuard tunnel (gVisor netstack) scoped so this machine can reach
**only its own host**. No TUN device is created and `run` does not need root.
The tunnel is dialled from this machine. Inside it, the bastion accepts on
exactly three addresses, all under the `inference` capability family: a
forward to a local ollama (port 11434), a forward to an OpenAI-compatible
server when one is configured (port 18080), and a forward to a local PII
sterilizer when one is configured. Nothing else listens.

### Git lane
A loopback HTTP proxy plus a `git-credential` helper, so your local `git` reaches
`git.privatae.ai` through your host. The forge answers platform addresses only,
so this lane is the way in. `privatae-bastion git-setup` prints the three
config lines: the proxy, a reset of the credential-helper chain for that URL
(so no other helper caches your token on this machine), and the helper itself.

### Worker lanes
Outbound-only reverse relays to the host: egress, management, harness, and
session. The management lane runs a **fixed-argv allowlist**. Ops that touch
your files are dedicated Go handlers with no shell. Of those file handlers,
the one that runs a program is text extraction: it invokes a local tool named
in a fixed table
(`pdftotext`, `ffprobe`, and the like) from a fixed argv template, and the
caller supplies only the tool's name and the document.

### Session lane
An interactive terminal that runs on this machine and streams to the host over
the same reverse WebSocket the other lanes use. No inbound port, no SSH server.
It is your own act in your Terminal app, and needs no standing grant from the
host (0.39.0): on a machine anchored to a host, `session:open` takes your
approval from your device or this console, bound to that one session; on a
local machine the pairing's caps are the authorization. A grant the host still
presents is verified as before, and a deny in it refuses. `session:open` runs
as an unprivileged user when the daemon is root. `session:root` runs as root
only when the daemon is root **and** you approved that specific session here
with the enrolled second factor. Every session is logged locally (output only) and recorded in the
pairing's audit file. Not available on Windows.

**Root commands (0.49.0).** The anchor host can also run one command at a
time as root, with no terminal and no approval per command, once you have
granted it here:

```sh
sudo -H privatae-bastion root-exec grant --host <anchor host> --for 30d   # asks for the code enrolled here
privatae-bastion root-exec [--host <host>]                               # what is granted, until when
privatae-bastion root-exec revoke [--host <host>]                        # take it back
```

The grant names one host (the anchor; a member pairing never gets it) and
this machine, ends at the time you chose, and is written only by that command
with the code; nothing the host sends can create, widen or extend it. Each
command runs as `/bin/sh -c` in its own process group, with a deadline (10
minutes unless the host asks for less or more, never more than 8 hours) and
with stdout and stderr returned up to a size cap (256 KiB each unless the host
asks, at most 4 MiB); a cut output keeps its start and its end and says how
many bytes were dropped. At the deadline the whole group gets SIGTERM, then
SIGKILL 2 seconds later, so a child that ignores SIGTERM goes too. The
bastion must run as root, the `session` family switched off here stops it,
and a quarantined pairing runs nothing. These are checked again every 2
seconds while a command runs: a revoke, the grant's expiry, the switch or a
quarantine stops a command already running, and its answer says why. Every
command is written whole, with its output (up to 64 MiB), to the context
store's `sessions/<id>.log`, and recorded at start and stop in the audit file
with its sha256, exit and byte counts; a refused, malformed or failed one gets
an audit row too. Not available on Windows.

The bastion also records where each root command connects. On Linux the
command starts in a cgroup of its own, and an nftables table the bastion
creates for that command records every connection the command and its
children open; the table only records (it never allows or drops anything)
and is removed when the command ends, or at the next start if the bastion
died mid-command. Destinations outside the platform's own hosts are returned
to the host as `untrusted_connections`, and the host then treats that output
as untrusted and ends root for the turn. List the platform's own hosts in
`platform_hosts.json` in the bastion's config folder:

```json
{"hosts": ["2001:db8::/32", "203.0.113.0/24", "git.example.org"]}
```

With no list, every connection that leaves this machine counts as outside;
loopback never does. A command whose connections could not be watched is
reported as if it had connected out. What it cannot see: connections another
program makes on the command's behalf, such as dockerd pulling an image for
`docker build`, or a service `systemctl` starts. A root command can also leave
its cgroup or delete the table on purpose; a missing table reads as "not
watched", but a command that leaves its cgroup is not detected.

### Context: your files, turned into text here
`add-folder` hands a folder to your network. `privatae-bastion context` opens a
browser page, running as **you** (not as the daemon), that shows exactly the
files you can already open and asks the host before anything is added. The
bastion can also turn bytes into content on your own hardware before anything
leaves: OCR for scanned documents, speech-to-text, office-document extraction
and video frames. Anything that turns your bytes into their content runs on
your machine, never on the platform.

### Distributed Context Network (DCN) stores
Signature-verified store grants for folders you share. The host's verify key is
pinned on first sync (trust on first use) and a later key change is refused.
Every read is sandboxed to the granted path, walks no symlinks out of it, and is
audited on this machine. The vocabulary is reads plus **one write lane**: a
signed move plan that you confirmed on this machine, which archives files and
never deletes them. Dropping a grant removes the grant, not your files.
**No delete op exists.**

### Model store
The host may manage which models live on this machine through the
`model:list`, `model:pull` and `model:drop` ops, under their own capability
family (`models`, separate from `inference`). Using a loaded model and deciding
what gets downloaded onto your disk are different permissions. A `model:pull`
needs your approval **on this machine**, is bound to that exact model, role and
byte ceiling, is good for one use, and is stopped if the download turns out
larger than approved. A machine with no second factor enrolled refuses
`model:pull` outright. `model:drop` refuses any model that this pairing did not
pull, so a model you fetched for your own work cannot be removed through that
op. A pull is reported available only after a behavioural probe, because a
completed download proves only that bytes arrived.

Note the boundary: those rules govern the `model:*` ops. The host's direct
traffic to the ollama forward inside the tunnel is filtered (store-changing
requests such as `/api/pull` and `/api/delete` refused, model names checked)
only when the pairing is **scoped to named models**, when you have switched
the `models` capability off in the local console, or when a networked
bastion's grant withholds model management. Otherwise, on a local bastion
with an unscoped pairing, that forward is a raw byte-for-byte splice to your
ollama, and the pairing itself is the authorization. Scope the pairing on
your host, or switch `models` off here, if you want the filter.

### Approvals with a local second factor
`stepup-enroll` enrols an authenticator on this machine. From then on a
request to install a folder grant, apply a move plan, pull a model, or open a
root session shows up under `privatae-bastion approvals` in plain words, and
you `approve` or `deny` it here with a code the host never handles. Without an
enrolled factor, folder grants and move plans are gated by the signed grant
alone and the host verifies its own factor; model pulls and root sessions are
refused outright.

### Writes on an anchored machine wait for your approval
On a machine anchored to a host, every management op is either a read or a
write. Reads answer on the anchor host's word. A write (a model drop, a
terminal, a job, a self-update, stopping a process, running a local tool to
extract a document)
runs only on an approval that this machine verifies and spends: bound to that
op, this machine and a digest of exactly its arguments, single use. You give
it either with the second factor enrolled here or from your **approval
device**: `device-init` makes one machine of yours the device, and
`pin-device <key>` on each machine you govern accepts what it signs. The
device shows each ask in the machine's own words and signs only that; a root
terminal still needs the code at the machine itself. Six kinds of write
take no fresh approval: standing work under a place you set up at the machine
(the nightly backup fetch, the host's context store), a run under op terms you
already approved (see Ops, below), a root command under the root-command grant
you gave at this machine with the code (see Session lane, above), the anchor
host's signed record of who else
may pair here, taking something away (a revoke), and a self-update to a newer
version we signed (see Heartbeat and self-update, below). A local, unanchored machine is unchanged: the pairing is
the authorization on your own computer.

The lane watches itself: five refused writes from one pairing within ten
minutes close that pairing's write lanes on this machine for ten minutes,
doubling on repeat. Reads and revokes are never held. `quarantine clear
<host>` lifts it.

### Ops: programs your host wrote, run in a sandbox first
A host can ship an op, a small program (`op.yaml` plus `run`) it wrote and
tested, identified by the sha256 of its contents. It runs here only under
terms the host signed and you approved: once, with these parameters, or as a
standing grant with parameter bounds, an expiry and a use count (never as
root). Every run is a dry run first, in a throwaway sandbox with no network,
an overlay over this machine's disks, and this bastion's own records masked;
it reports what the op would create, change and remove. An op sees only the
system's programs and libraries, a few `/etc` files that hold no secret, and
the paths its manifest declares (its effects and its `reads`). Every other
file and folder is covered with an empty one. A link is left in place, so an
op can read where a link points, but not what is there. The op can also see
the names of the folders it was denied, in its own mount table. A declared
path that reaches a credential store is refused, as written and as it
resolves, and checked again at every run. The stores are `/root`, `/etc/ssh`,
`/etc/shadow`, `/etc/wireguard`, `/etc/systemd`, docker's and k3s's keys and
more, plus any path you list in this machine's `sensitive_paths`. Covers are
put on paths, so a bind mount or a hard link that you make yourself, putting
a credential file inside a declared path, is seen through it. List such a
path in `sensitive_paths`. Anything outside the
op's declared file effects refuses the run. Applying is the same run again,
then a check in a fresh sandbox. A one-time apply is bound to the change list
the dry run showed you, and lands nothing else. A run under a standing grant
is bound to the grant's parameter bounds and the op's declared effects
instead: you approved the grant, not each run's change list. Linux only, and file effects only; other platforms refuse every op
and say so. `privatae-bastion ops` lists what is held, and `ops drop <grant>`
takes a standing grant back.

### Action ops: ship steps, run the same way
A ship step acts rather than edits: it builds and pushes an image, moves a
source tree to a new commit, restarts a service, rolls a workload. An op with
`kind: action` does this in two parts, and approving it works the same way:
a dry run first, then an apply bound to the change list the dry run showed.

- **The op's program runs unprivileged.** Each run gets a uid no earlier run
  had, in its own systemd transient unit, with no capabilities and no new
  privileges. This machine's files
  are read-only to it: it writes only to a private work folder at `/tmp` and
  its own throwaway `/run` and `/var/tmp`. It sees only what a files op sees
  (above).
- **Its network, in an apply,** reaches only the `destinations` it declares
  (`host:port`):
  - the unit's address allowlist holds it to the addresses those names
    resolved to when the run began;
  - Landlock holds its TCP connections to the declared ports, and blocks
    abstract unix sockets and signals outside the sandbox;
  - UDP is held to the declared addresses but not to their ports, and a port
    declared for one address is open on every declared address;
  - a destination on this machine, a link-local address, or a cloud's
    metadata service is refused, as written and as resolved.

  **A dry run has no network at all,** because nobody approved it.
- **Memory: no ceiling, and the op goes first.** A run may use whatever
  memory the machine has to spare. It is the first thing stopped when the
  machine runs short:
  - the kernel, if it must kill, kills the op before anything else;
  - the bastion stops the op when free memory falls to a floor. The floor is
    the largest of 1 GiB, 5% of memory, and, on a Kubernetes node, the
    kubelet's own eviction line (hard or soft) plus 512 MiB, so the op goes
    before any pod is evicted. A kubelet setting it cannot read raises the
    floor, never lowers it;
  - the bastion also stops the op when the machine's services, pods or users
    start waiting on memory: 7 points more of the time than the least they
    had during the run. The op's own waits don't count, and neither does a group that was
    already waiting, such as a pod at its own limit;
  - a machine already under the floor starts no op;
  - a run counts as stopped only if the kill landed.

  The refusal says what happened and how much the op had used.
- **Credentials:** it is handed the `credentials` it declares, sealed by the
  host to this machine's encryption key and bound to that run, in its
  environment only. A credential a verb names goes to the verb, never to the
  program. They are scrubbed from its output and gone when the run ends. A
  dry run is handed none.
- **The builder:** an op that declares `builder` reaches this machine's
  builder socket in an apply, never in a dry run, and never through a
  privileged group.
- **Root work is done by this bastion, as named verbs** the manifest declares
  with their arguments written in:
  - `tree.checkout` moves an existing git tree forward to an exact commit from
    its own origin. It runs only in a tree root owns, whose `.git` no one
    else can write, and never writes into a folder another user controls. It
    never runs the tree's hooks, never overwrites an ignored file the machine
    keeps, and refuses a tree with local changes or a git config that could
    run a program.
  - `unit.reload` and `unit.restart` act on one systemd service, never the
    bastion's own.
  - `k8s.set_image` sets one container's image to a digest, only forward:
    - the digest needs a receipt this machine signed for an image one of its
      op runs reported, built from the repository the manifest names;
    - its commit must descend from the one behind the live image;
    - the live image's commit counts only if this machine rolled it. An
      image it did not roll is refused, and the refusal says so.
  - `logs.check` returns a verdict and one line, read after the apply.

  Only a commit and a digest may come from the run's parameters. The program
  cannot ask for a verb. An op with verbs is root, so it is never a standing
  grant.

What a program pushed becomes a receipt, signed by this machine. The
heartbeat says whether this machine can run action ops (`action_ops`) and
carries its encryption key, signed by the machine's own key. A run that
this bastion's restart cut short leaves nothing: the next start unmounts
its files and stops its unit.

### Ship plans: one approval for a whole ship
A ship is several action ops on several machines, in order: build and push
on one, move a tree and restart on another, roll a workload on a third. Your
device signs **one plan** listing every step, and each machine runs only its
own lines of it.

**What your device signs:**
- the pipeline, a version that only goes up, the commit being shipped, a
  nonce, and an expiry of at most four hours;
- each step: its machine, its op and that op's sha256, its params, the verbs
  it will run, the params it takes from an earlier step's receipt, and whether
  it may be undone;
- the key of every machine in it. The device fills these in from its own pins
  (`pin-machine`), never from your host. When you pin your device on a
  machine, the machine prints the exact `pin-machine` line to run on the
  device.

**Before signing, the device:**
- refuses a plan naming a machine it has not pinned;
- asks for your code when a plan runs root work, checks it against the
  factor enrolled on the device's own pairing (never one the ask names), and
  says in the plan that it did;
- keeps such a plan out of "approve all shown";
- shows every field as plain text: a plan whose params, inputs or verbs hold a
  control character, a line break or a Unicode direction mark is refused, so
  nothing in it can redraw or hide what you read.

**Each machine, before it runs a line, checks that:**
- the plan is signed by a device pinned there;
- it has not expired, and it is not older than a plan it already ran for that
  pipeline;
- it names this machine's own key for this machine;
- the line is for this machine, and has run fewer times than the plan
  allows (once, unless you approved retries). Its attempts run one at a
  time: the next only after the last one failed, never after one passed, and
  never after the step was undone. The machine keeps this record itself, and
  an attempt the bastion died in counts as failed. A tree or workload
  something else moved since the line's changes were read — while its
  program ran, or between two attempts — is left alone: the verb refuses
  it, so an undo can never take that other change back. Changes this
  bastion makes to one tree or workload, forward or undo, take turns;
  a change from outside is caught one command before the write;
- every line before it succeeded, shown by their signed receipts, so a check
  never runs before the step it checks;
- a root line comes with your code;
- the op it holds declares exactly the verbs the line showed you.

**Values that don't exist when you approve,** like the digest a build
produces, come from receipts. Each line ends in a receipt signed with the key
your device pinned for that machine, and the machine keeps it for your host
to read back (`op_plan_status`). A roll takes its digest only from a
successful earlier step of the same plan, at the plan's commit: the image the
plan's own build step reported, never one from another run. That rests on the
build op reporting truly, and that op is one you approved in the plan. The first roll on a machine with no
record of its live image says so on the device, and takes that image as its
starting point.

**Undo.** A step marked undoable is taken back once, to the state that
machine recorded before the step's first attempt. The machine records each
change before it makes it, so a retry, or a change the bastion died in the
middle of, is taken back too. An undo takes one of two signed receipts:
- a later step of the same plan failed its check (its apply ran, its verify
  or log check did not pass) on the last attempt the plan allows it, so no
  retry of it can still pass;
- the step's own latest attempt failed, and none of its attempts passed.

The tree or image goes back first; a unit the step restarted is restarted
after, on what was put back. A tree or workload that moved since is left
alone, and a file the machine keeps is never overwritten. Once undone, the
step never runs again.

### Service slot: a server your host built, with no network
A host can leave a server running here, such as a private git server: an
image started with every capability dropped, no new privileges, one data
directory, and **no network at all**. It serves on a unix socket, and the
host's tunnel is the only way in; the bastion checks on every connection that
the socket belongs to the server's own user. Reaching a server needs a reach
grant you approved, naming that host and that server. If the server should
mirror public repositories, this machine does the fetching over its own
connection (public internet only, https, no redirects) and pushes into the
server. It is its own capability family, `services`. Linux only, and only
where a container runtime is installed.

### Observe: what is running on this machine
Read-only, and reported so the host can show **why** rather than a verdict.

- **Agent observe.** Watches for AI-agent activity two ways and correlates by
  process: a process signal (known agent binaries, interpreter-wrapped ones by
  command line) and a network signal (connections to inference endpoints, both
  cloud APIs and local model servers). Each observation carries an **origin**
  (`interactive`, `remote`, `scheduler`, `service`, `agent`) and a typed
  evidence list with a confidence tier. Tools that drive the machine with no
  model of their own are inventoried as `automation` and promoted to `agent`
  only when model traffic joins them.
- **Scheduler inventory.** Crontabs, `systemd` timers, `launchd` jobs and
  Windows scheduled tasks whose command would run an agent or automation.
- **Baseline and delta.** `observe:baseline` records what is normal on this
  machine: every automated program, its user, and a digest of the file it runs
  from. `observe:delta` reports what the baseline does not hold, with ordinary
  noise filtered out. Administrator only.
- **Computer observe.** The machine map the host plans from instead of a
  screenshot: installed applications with their scripting doors, the windows
  open now, and one app's accessibility tree as exact text. Read-only. No input
  injection lives in the bastion.
- **Host observe** (Linux). Sockets, firewall, failed units and timers, disk,
  kernel log, and a read-only Kubernetes view where the control-plane installer
  has placed a `view`-bound kubeconfig. Every argv is fixed. Off Linux each of
  these answers `unsupported`. The one exception is `observe:net`, which is
  pure Go and works on every platform: given a `host[:port]` it makes an
  outbound probe **from this machine** (TCP connect, TLS expiry and chain,
  HTTP status).
- **Monitoring observe** (`observe:alerts`, `observe:metrics`, `observe:logs`).
  The pull half of the same family: read-only HTTP against an Alertmanager,
  Prometheus and Loki running on the box's own network, named once at install
  in a local config file. Only private addresses are accepted — the reverse of
  `observe:net`'s public-only rule, since these read the box's own
  neighbourhood. `observe:alerts` reports the active Alertmanager set;
  `observe:metrics` and `observe:logs` each take one name from a fixed list
  and the box owns the query — no PromQL or LogQL ever crosses the wire from
  the host. Alert counts also ride the heartbeat, refreshed on their own
  interval, and are absent — not zero — whenever no Alertmanager is
  configured.

The observe ops that send traffic are `observe:net`, `observe:k8s` (a
read-only query of a cluster API) and the three monitoring ops above (private
addresses only, refused at the socket if a redirect or a DNS answer would move
the destination after validation). A build with no enumerator for its
platform **withholds** the capability, so the host can tell a machine that is
quiet apart from one that is blind.

### Heartbeat and self-update
Each check-in carries the machine's capabilities, posture, agent scan and
scheduler inventory. The host can direct endpoint rotation and a self-update.
The update is fetched from the release manifest; the manifest's signature is
checked against the release keys compiled into this binary and the binary's
digest against the manifest before it is swapped. On an anchored machine a
move to a newer version needs no approval from you: our signature on the
release is the approval, and the update goes ahead only when the signed
manifest names exactly the version your host asked for. A move to an older
version, or to one this build cannot compare with its own, waits for your
approval, bound to that version. Switching `directives` off in the local
console refuses both.

### Memory mirror
When your host asks for it, the bastion keeps a streaming replica of the
host's database on hardware you own: a PostgreSQL standby running the same
image the host runs, fed through a forwarder in this process that carries the
replication stream over the tunnel. The host decides whether a mirror exists
and when a copy is void; this machine holds the copy. The forwarder listens
on loopback and on the replica's private container-network gateway address,
never on all interfaces, and every accepted connection is source-checked
against the replica's subnet. The data on your disk is ordinary PostgreSQL
files, unencrypted: it is your copy, readable with your own tools, and
full-disk encryption on your machine is the protection.

### Backups: this bastion's key, and a host's restore
Your host encrypts each of its backups before the backup leaves it, to the
host's recovery key (which you keep) and to every bastion key you registered
with it. The platform holds none of those keys. This bastion can hold one:
`privatae-bastion backup key init` makes it here and prints the three fields
to register on your host (kind `bastion`, a label, and the public key). The
key is a standard age key file, 0600, in the bastion's own state folder; only
its public half ever leaves this machine. `backup key init --replace` makes a
new one and keeps the old one beside it, because the backups made before
still need it.

Each backup also carries its own key, sealed in a small sidecar file next to
it to the same keys. When a host restores a backup, it asks this
bastion for that one backup's key (`backup_reseal`). Nothing is opened until
you approve the request here: `privatae-bastion backup requests` shows which
backup and which host, and `backup approve <id>` shows the pairing the
request came in on and its host number (this machine's own record, from
pairing), what the host says, and what the sidecar itself says, opened here
(the host number, when it was made, which backup). A sidecar of another
host's backup is refused, whatever the request calls itself: a host is given
only its own backups' keys. Restoring a lost host's backups onto the host
that replaces it is yours to do here, with `backup restore-plan`. Approving
(with the code from your authenticator, when one is enrolled for that host
here) checks the sidecar is the backup the host asked for, of a backup kept
in platform storage (`b/`) or staged there for a copy kept only here (`s/`),
and seals the same record to that host's own key alone. The
host then fetches and decrypts that backup itself. This bastion's key never
leaves this machine, and the host gets a key that opens that one backup and
no other. A host can hold at most 16 requests waiting here, or 512 KiB of them;
answering one frees its room, and a request lapses after a day. The daemon
and `backup approve`/`deny` lock the request file while they change it, and a
request file that cannot be read is set aside beside it and named by `backup
requests`, not overwritten.

When your host keeps a copy of its backups on this machine, they arrive
through `backup_fetch`, each with its sidecar, named `<stamp>.tar.zst.age` and
`<stamp>.key.age` (the stamp is the backup's UTC time, `YYYYMMDDTHHMMSSZ`).
Files named that way always land at the top of this host's backup folder,
whatever folder the host names. This bastion keeps a record, in its own state
folder, of every backup file it fetched: when it arrived, its size and its
SHA-256. After each one arrives, the folder is thinned among the files in that
record only, and only while each is still the file that arrived: the newest 7,
and the newest of each of the last 14 days, 8 weeks and 12 months, judged by
when each file arrived here, not by the name the host gave it. Files you put
there, files from before this version and anything else in the folder are
never removed. A file named `.keep-all` in the folder turns thinning off.

Each host's backup folder must be its own. A backup op is refused while the
folder is the same as another paired host's, sits inside it or contains it;
while it is or contains this bastion's configuration folder, backup keys or
backup records; or while it sits inside the configuration folder anywhere
but under its `backups` folder (the default, `backups/<host>`, is there). Set
a separate `backup_root` for each host to use one. Every host's backup folder, wherever it
is, is part of this machine's own record for ops: no op may name it as an
effect, and the sandbox hides it. One on a network mount that stops
answering is left unmasked for a run rather than stopping it, and no op may
name it all the same.

A host can list the backups held here for it (`backup_list`): each backup's
stamp, the sizes of its data file and sidecar, and their SHA-256 digests. A
listing never reads a file to hash it: a digest this bastion does not know yet
is left empty and read in the background, and appears on a later listing. A
file whose read does not return within two minutes (a network mount that
stopped answering) holds up no other folder: the background reading moves on,
reads nothing more from that folder until that read returns, and keeps its
digest if it does. The two minutes count from the last read of the file that
returned, not from the start of the file: a large backup on a slow disk whose
reads keep returning is read to the end however long it takes, and never
counts as stuck. To
restore a backup held only here, the host asks this bastion to send one of
those files to a short-lived upload address (`backup_push`): only a file named
like a backup, directly inside this host's backup folder or a folder you
shared with it, not through a link that leaves that folder; only the file
whose SHA-256 the host names, checked before anything is sent; only over https
to a public address that is not this machine's own, with the header the address was signed with (the
platform signs `If-None-Match: *`, so storage never writes over an object that
is there); that header with that value is the only one a host may hand over,
and any other header name or value is refused before a job starts, as is a
start with no headers at all (the platform always hands that one over). A push
whose file stops answering (a stat, the open or one read of it not returning
within two minutes, as on a network mount that died) fails with a sentence and
its upload is stopped, rather than staying pending. The read it was stuck in
cannot be stopped and keeps a thread and the open file until the mount
answers. Pushes and the background reading for digests keep one record of
their reads, so a folder holds at most one stuck push read and one stuck
digest read however often a push is started there, and the whole bastion at
most eight reads of both together: a start in a folder with a read of either
kind that has not returned is refused with a sentence, as is any start while
eight reads have not returned, until one does; the reading for digests skips
a folder whose push read has not returned, and reads nothing while eight are
in flight. A push that waits for its turn to read (behind a stuck read) is
not blamed for it: after two minutes of waiting it fails with a sentence
naming what it waited on, its folder's stuck read or the cap of eight. A job's status answers only the host that started it,
and no reply quotes the upload address's signature.

### Restoring a lost host
If a host is lost, a new one is made to replace it, and it restores from a
backup. The new host needs two things: that backup's key, and the backup file.

The key: the new host shows its own key under Settings > Backup > Restore.
Either this bastion reseals the backup's key to it — through a restore request
from the new host once this bastion is paired with it, when the new host has
the lost one's host number (a request for another host number's backup is
refused), or, for any host, here with
`privatae-bastion backup restore-plan --dir <folder> --stamp <stamp> --to
<the new host's key>` — or the owner does it in their browser with the lost
host's recovery key, which is also a recipient of every sidecar. Either key
works; the new host never receives either of them.

The file:

- from platform storage or your own S3 bucket, a new host finds the lost
  host's backups only if it has the same host number as the lost one;
- from this machine: pair this bastion with the new host, then share the lost
  host's folder with it, here, with
  `privatae-bastion backup share --with <new host> --from <lost host>` (or
  `--dir <folder>` for any folder). The new host then sees those backups in
  its listing as `shared/<name>` and asks this bastion to send the one it
  needs. It cannot write to that folder. `backup unshare` takes it back, and
  unpairing or revoking the new host takes back every folder shared with it.

This bastion does not bring up the new host. Running one on hardware you own
needs infrastructure that is not part of this program, and not built yet:

- a DMZ cluster on your hardware: a Kubernetes cluster with the network
  policy, admission and storage the host's pod expects;
- the operator that creates and runs a host's pod on that cluster;
- the host's container images, from a registry that cluster can pull from;
- the certificate authority that issues the host its identity, and the
  services a host reaches when it starts, or replacements for them;
- a place the new host can fetch the backup from, as above.

### Local console
`privatae-bastion ui` opens a page served by the running daemon on `127.0.0.1`
and reachable from nowhere else: pairings, the anchor, containment state, marks
on automated programs, the dry-run policy, and pending approvals. On Windows
a tray icon shows a one-line state and offers four actions: open what is
waiting for your approval, open the console, open your context page, and stop
the bastion.

### Approvals from the taskbar
On the machine that is your approval device (`device-init`), every ask a host
files for one of your machines raises a notification on Windows. Clicking it, or the
tray's approvals line, opens the approvals window: each ask in plain words,
with Approve and Deny, and "Approve all shown" when there are several. Approve
signs with this device's key exactly as `device-approve` does: one run, on the
machine the ask names, within the hour. "Approve all" signs only the asks the
window showed you, never one that arrived after. The same window lists the
requests waiting for a code on this machine itself. The window does not
redraw by itself while you read it: when something new arrives it says so and
waits for you to show it. Off Windows the window is a page of the local
console (`privatae-bastion ui`, then Approvals in the header).

## Command reference

| Command | What it does |
|---|---|
| `pair <token>` | Enrol this machine with a host. Each pair adds a host; re-pairing an existing host is refused. |
| `pair -` | The same, with the token as the first line of standard input, so it is not in the process list or your shell history. Only `-` reads standard input: `pair` with no token is the usage error. Every form of `pair` takes `-` in place of `<token>`. |
| `pair --replace <token>` | Re-pair an existing host: rotates its credentials, keeps its port, context store and DCN state. |
| `pair [--replace] --redeem-url unix:///<socket> <token>` | Pair with a Host on this machine over its enroll socket. Its CA is pinned for life. See [A Host on this machine](#a-host-on-this-machine). |
| `pair [--replace] --redeem-url https://<host>:<port>/<path> --host-ca <pem> <token>` | Pair with a Host in a VM on this machine over its enroll port, trusting that CA alone. Its CA is pinned for life. See [A Host in a VM on this machine](#a-host-in-a-vm-on-this-machine). |
| `run` | Bring up the tunnel and lanes for every paired host. |
| `status` | Show every pairing and its tunnel status. |
| `ui` | Open the local console in your browser. |
| `add-folder [--host <host>] <path> [name]` | Add a folder to your network. `--host` is required when more than one host is paired. |
| `context` | Choose what your files become on your network. Runs as you. |
| `stepup-enroll [--host <host>] [--rotate]` | Enrol (or rotate) the second factor on this machine. |
| `approvals [--host <host>]` | List what your host is asking to do here, in plain words. |
| `approve [--host <host>] <id>` / `deny …` | Answer one request with a code from the authenticator enrolled here. |
| `approvals drop [--host <host>] <id>` | Take back an approval this machine issued and has not used yet. |
| `grants drop <store id> [--host <host>]` | Remove a folder grant held on this machine. The host is told. |
| `device-init` | Make this machine your approval device. |
| `device-approvals` | What your machines are asking you to approve, in their words. |
| `device-approve <id>\|all [--code <code>]` / `device-deny <id>` | Approve or refuse from the device. `all` signs only the asks the last listing showed, and never a ship plan that runs root work: that takes `--code`. |
| `pin-device <key>` / `unpin-device <key>` | On a machine you govern: accept (or stop accepting) approvals signed by your device. Root required. Prints the `pin-machine` line to run on the device. |
| `pin-machine <host> <key>` / `unpin-machine <host>` | On your device: pin (or drop) a machine's key, as that machine printed it, so the device can sign ship plans that include it. |
| `ops [--host <host>]` | The ops your host wrote that this machine holds, and the standing op grants. |
| `ops drop <grant> [--host <host>]` | Take back a standing op grant. The host is told. |
| `coders set [--max N] [--mem MB] [--cpus F] [--engines a,b\|all] [--allow-lan host[:port],...] [--image-prefix <registry/path/>\|default]` | Size this machine for coding runs your hosts place here: how many at once, memory and CPUs per run, which engines, LAN hosts a run may reach, and where run images may come from (`<prefix>harness-<engine>@sha256:...`; default `git.privatae.ai/privatae-harness/`). Does not switch them on. |
| `coders on` / `coders off` | Allow coding runs here (Linux, bastion running as root), filling unset sizes with defaults; or stop new ones. Off by default. Each run is a container with no network of its own; it reaches the public internet through this bastion and never this machine or its LAN. |
| `coders drop [--host <host>]` | Take back the standing coder grant of every host, or one, and stop their runs. |
| `coders status [--json]` | The coder settings, grants and runs on this machine. |
| `quarantine clear <host>` | Reopen a host's write lanes that this machine closed after repeated refusals. |
| `git-setup` | Print the `git config` lines that route `git.privatae.ai` through this bastion. |
| `git-credential` | Git credential helper. Fetches your forge token from your host on every auth. |
| `unpair <host>` | Tear down one pairing. Context store and DCN state are left in place. |
| `set-mode <local\|networked>` | Switch modes. Root required. |
| `claim-anchor [--owner <name>] [--host <host>] [<token>]` | Networked mode: make a host the anchor. No token when the host is already paired here. Also `--rotate <token>`, `--repin`. Root required. |
| `claim-owner <name>` | State who owns this machine. Root required. Optional; grants nothing. |
| `observe` | Print the agent, automation and scheduler snapshot the next check-in would carry. |
| `observe:baseline [--force]` | Record what is normal on this machine. Administrator only. |
| `observe:baseline:show` | Print the baseline this machine holds. |
| `observe:delta [--json]` | What is running that the baseline does not hold. Administrator only. |
| `backup key init [--replace] [--label <name>]` | Make this bastion's backup key and print the fields to register on your host. `--replace` keeps the old key. |
| `backup key show` | The backup key this bastion holds, and the older ones it keeps. |
| `backup requests [--host <host>]` | Restore requests your host sent this machine. |
| `backup approve [--host <host>] <id>` / `backup deny …` | Answer one: approving seals that one backup's key to the requesting host. |
| `backup reseal --sidecar <file> --to <host key>` | Seal one backup's key to a host's own key, offline. |
| `backup restore-plan --dir <folder> [--stamp <stamp> --to <host key>]` | List the backups in a folder; reseal one for the host that replaces a lost one. |
| `backup share --with <host> (--from <host> \| --dir <folder>)` | Let a paired host list and ask for the backups in another host's folder (or any folder). |
| `backup shares --with <host>` / `backup unshare --with <host> <name>` | The folders shared with a host; take one back. |
| `version` | Print the version. |

Run `privatae-bastion` with no arguments for the built-in help.

## Security model

- **The bastion dials out.** Every lane is a reverse connection from this
  machine to the host. No port is opened on an externally reachable interface;
  the control ports and console bind loopback only, and the optional
  memory-mirror forwarder binds loopback plus the replica container's private
  gateway address, with every accept source-checked.
- **Inside the tunnel, only gated listeners.** The host can connect to up to
  three inference forwards (local ollama, an OpenAI-compatible server, a PII
  sterilizer), each a proxy to a service you run, on loopback by default and
  elsewhere only if you point it there by environment variable; and to one
  port per server in the service slot (18100 to 18199), joined to that
  server's socket; and to one port per coder run (18200 to 18299), joined to
  that run's control socket. Every connection is checked when it is accepted: a forward
  needs the pairing to hold the `inference` capability family, a service
  slot port needs the `services` family and a reach grant for that server
  naming that host, and a coder run port needs the `harness` family, the run
  to be that host's and within its deadline, and the connection to come from
  that host's own tunnel address. Nothing else in the tunnel accepts a connection.
- **A Host on this machine gets the same walls.** Its lanes go over its lane
  socket with mutual TLS against the CA pinned at pairing, the pairing's name
  checked and the bearer on every lane; a pairing with no bearer opens none.
  A coder run it owns is a socket in its own runs directory (0660, group
  `privatae-host`, else root), checked at every accept as a run port is, and
  removed at run-down and at the watchdog's stop. The runs directory must be
  one only root can change (root's, writable by nobody else, under
  directories that are root's and not writable by others unless sticky), or
  no socket is made in it. On an anchored machine its run-up needs the
  standing coder grant like any pairing's.
- **Scoped tunnel.** The WireGuard peer's only allowed address is the paired
  host's single tunnel address, so the tunnel can reach nothing else. A
  pairing that offers anything wider is refused, and a pairing file that
  holds one brings no tunnel up.
- **No MCP endpoint.** Nothing on this machine drives the host.
- **Grants are verified here.** What the host may do arrives signed. The verify
  key is pinned on first use, and a deny always beats an allow.
- **Fixed argv.** Every management op runs a fixed command line. File ops are
  dedicated Go handlers with no shell. Text extraction runs a named local tool
  from a fixed template.
- **Approval on the machine, once enrolled.** With a second factor enrolled
  here, folder grants, move plans, model pulls and root sessions each need a
  code from this machine, bound to that exact request, single use. Without
  one, grants and move plans rest on the signed grant alone, and model pulls
  and root sessions are refused.
- **On an anchored machine, a write needs an approval verified and spent
  here.** It comes from the second factor enrolled here or from your pinned
  approval device, is bound to the op and a digest of its arguments, and is
  used once; with neither enrolled, those writes are refused. The exceptions
  take no fresh approval: standing work under a place you set up at the
  machine (backup fetch and backup push, the host's context store), a backup
  restore request (approved on its own, below), runs under op terms you
  approved earlier, a root command under the grant you gave here with the
  code, the anchor host's signed pairing records, revokes, and a
  self-update to a newer version we signed. Repeated refused writes close a pairing's
  write lanes for a while.
- **Host-written programs run sandboxed first.** An op runs only under signed
  terms you approved, as a dry run in a sandbox with no network, and never
  changes anything outside its declared file effects. A one-time apply lands
  only the change list you saw; a run under a standing grant is held to the
  grant's bounds.
- **A server in the service slot has no network.** The host's tunnel is its
  only way in, and it cannot reach this machine, your network or the
  internet.
- **Egress for someone else reaches the public internet, never this
  machine.** A coder run's proxy, always, and the egress lane on an anchored
  machine refuse loopback, link-local (the cloud metadata address included),
  private, CGNAT and reserved addresses, and any address this machine takes
  as its own: one on its interfaces (a public one included), and on Linux any
  address the kernel's routing table delivers here (a `local`, broadcast,
  anycast or multicast route, such as an AnyIP range on `lo`), asked of the
  kernel per connection. The IPv4 address inside an IPv4-mapped, NAT64 or
  6to4 address is checked too, every address a name resolves to is checked,
  and the address checked is the one dialled. When the machine cannot tell,
  it refuses. A coder run reaches a LAN host only when you named it in
  `coders set --allow-lan`; the anchored egress lane has no such exception.
  The anchored lane's refusal of this machine's own non-private addresses is
  new in 0.50.0; before it, that lane refused only the internal ranges. A
  local (unanchored) machine's egress lane is unchanged and vets no
  destination. The backup lanes (`backup_fetch` and `backup_push`, anchored
  or not) apply the same check of this machine's own addresses, to every
  address the URL's name resolves to, to each redirect a fetch follows and to
  the address dialled; this too is new in 0.50.0, and before it they refused
  only loopback, private, link-local, multicast, unspecified, CGNAT and ULA
  addresses. Also since 0.50.0 they classify an address as a coder run's
  proxy does: the IPv4 address inside a NAT64 `64:ff9b::/96` or 6to4
  address is judged, and IPv4-compatible and IPv4-translated addresses, the
  rest of `64:ff9b::/32`, site-local `fec0::/10`, `0.0.0.0/8`,
  `198.18.0.0/15` and `240.0.0.0/4` are refused. Not covered: a public
  address that reaches this machine only through a 1:1 NAT in front of it,
  which is on no interface and in no local route. The bastion does not learn
  that address.
- **A terminal is checked here and logged.** On a local (unanchored) machine,
  a terminal opens when the host asks, with no approval. No signed grant is
  needed, but one that is sent is verified, and a deny in it refuses. On an
  anchored machine, a host other than the anchor needs the `session` family
  in its pairing grant, and each terminal needs an approval from your pinned
  approval device or the second factor enrolled here, bound to that one
  session and used once. A root terminal, on either kind of machine, needs
  the bastion to run as root, a second factor enrolled here, and a code
  entered on this machine for that session; an approval device cannot approve
  it. Each session, and each refusal of a well-formed request, is written to
  the audit log on this machine when the pairing has a grant store; a
  malformed request is refused with no audit line.
- **Root commands run only under a grant given here with the code.** Only
  the anchor host can hold it. It names this machine, ends when you said, is
  revoked from this console, and needs the bastion to run as root. A revoke
  or an expiry also stops a command already running, within 2 seconds. Every
  command and its output is written to a transcript here and to the audit
  log; refusals, malformed commands and setup failures are audited too.
- **Root only where there is no one else to ask.** Claiming ownership or the
  anchor requires root because those are machine-wide facts.
- **On macOS and Windows, a networked bastion is the system's service.** It
  runs as root under launchd, or as LocalSystem under the Windows service
  manager, starts at boot and is restarted when it stops, so the signed-in
  user cannot stop it. It is registered only from a program that only root or
  an administrator can replace. Beside it, `pair`, `run` and `status` from an
  account that does not administer the machine are refused, so this binary
  will not start a second bastion in that account. An older or modified copy
  is not bound by that refusal; what keeps the service in place is that the
  signed-in user does not administer the machine.
- **Observation changes nothing on the machine.** Observe ops read and report.
  No input injection lives in the bastion. The observe ops that send traffic
  are `observe:net`, an outbound probe to a host you name; `observe:k8s`, a
  read-only query of a cluster API; and the three monitoring ops
  (`observe:alerts`, `observe:metrics`, `observe:logs`), read-only HTTP
  against an Alertmanager/Prometheus/Loki on the box's own network —
  private addresses only, re-checked at the socket so neither a redirect nor
  a DNS answer can walk a query out of that neighbourhood.
- **A backup's key goes to a host only when you approve it here.** A host's
  request to restore files a request and gets nothing until you approve it
  on this machine; the key sealed to the host then opens that one backup and
  no other, and this bastion's key never leaves this machine. Thinning the backup
  folder removes only backup files this bastion recorded fetching, still as
  they arrived, judged by arrival here. A host sends from this machine only
  backup files in its own folder or a folder you shared with it.
- **No delete op on shared stores.** The one write lane is a move plan you
  approved, and it archives rather than deletes.
- **Verified releases.** The self-updater checks the release manifest's
  signature against the release keys compiled into it, then checks the
  binary's SHA-256 against that manifest before anything is swapped. The
  agent download is checked the same way, and an installed agent is never
  replaced with an older one. The release key never reaches the machine that
  builds and publishes: each release waits until the key holder signs it on
  their own computer. The installer checks the SHA-256; see
  [SECURITY.md](SECURITY.md) for what that does and does not prove.
- **No secrets cached for git.** The credential helper fetches a token from
  the host on every auth and stores nothing itself, and `git-setup` resets
  the forge's helper chain before adding it. With git 2.46 or later, git's
  own store and cache helpers keep nothing, wherever they are configured; a
  helper that records everything it is given still receives the token. A git older than 2.46 gets the username
  and password, and for it only helpers configured before `git-setup`'s
  lines are kept out.

### How each claim is tested

Each row names a test in `client-go/` that fails if the claim it sits under
stops being true. Where a claim, or part of one, has no such test, the row
says so. Those parts are enforced only by the code as written.

| Claim | Test (file: function) | What it asserts |
|---|---|---|
| The bastion dials out | `config_test.go`: `TestNextListenAddr` | Each pairing's control port is allocated on `127.0.0.1`, from 7878 up. |
| | `mirror_test.go`: `TestMirrorPeerAllowed` | The memory-mirror forwarder accepts only loopback and the replica's own subnet; a LAN address, the default container bridge or an unknown subnet is refused. |
| | `claims_static_test.go`: `TestEveryListenerThisPackageOpensIsInTheTable` | Every listener this package opens outside the tunnel is in a table with its number of call sites; the console, the context page, the mirror push bridge and the action-op probe bind loopback, and the mirror forwarder binds its gateway and loopback. The WireGuard device's own UDP socket is opened in the wireguard module, not this package, and is not in the table. |
| | `claims_static_test.go`: `TestListenAddressesAreOnlyEverAllocatedOnLoopback` | The control and git port addresses are set only by the loopback allocators, or kept from the pairing being replaced. |
| Inside the tunnel, only gated listeners | `anchor_test.go`: `TestInferenceLaneIsCapsGated` | A pairing without the `inference` family has its forward connections closed and the forwards left out of its heartbeat; granting the family opens them without a restart. |
| | `service_reach_test.go`: `TestReachGrantSyncAndTheForwardWall` | Installing a reach grant is refused without an approval, for another host, or for another machine. `serviceReachAllowed`, the reach check a slot port runs, then admits the granted host to the granted server only; another server, another host or a revoked grant is refused. The check is called directly, not through the slot listener. |
| | `claims_unix_test.go`: `TestEachInferenceForwardAdmitsOnlyThePairingThatHoldsInference` | Through each forward's accept loop on an in-memory tunnel: a pairing without `inference` never reaches the upstream, and granting the family lets the next connection through, with no restart. |
| | `claims_unix_test.go`: `TestTheServiceSlotAdmitsOnlyWithTheFamilyAndAReachGrant` | Through the slot listener: a connection is refused with a reach grant but no `services` family, and with the family but no reach grant for that server; with both it reaches the server's socket. |
| | `claims_static_test.go`: `TestOnlyTheGatedForwardsListenInsideTheTunnel` | Every listener on the tunnel's network stack is one of the four gated forwards, each at one call site; only they are handed the stack, and it is otherwise only dialled out of. |
| | not covered by a test | The reach check's own comparison of a stored grant's machine (`service_reach.go`, `serviceReachAllowed`). |
| Scoped tunnel | `claims_tunnel_test.go`: `TestTheTunnelReachesOnlyThePairedHost` | A WireGuard device configured the way a pairing configures it holds one peer, whose only allowed address is the host's /128, before and after an endpoint rotation. |
| | `claims_tunnel_test.go`: `TestATunnelAddressThatIsNotOneHostIsRefused` | A tunnel address that is a prefix, empty, zoned, unspecified, multicast or not an address is refused at tunnel start and at a rotation, and the device is left with no peer. |
| | `claims_static_test.go`: `TestARotationReachesTheDeviceOnlyThroughSwapPeer` | A rotation, a failover and a probe change the live peer through `swapPeer`, the function the two tests above drive: the variables they call it through are declared with it and never assigned or addressed outside tests. |
| | `claims_unix_test.go`: `TestAPairingResponseWithAWideTunnelAddressSavesNothing` | A pairing response that offers a prefix is refused and leaves no file in the config dir; one that offers a single address pairs. |
| | `claims_unix_test.go`: `TestRunPairingRefusesAWideTunnelAddress` | A pairing file that holds a prefix brings no tunnel up. |
| | `fuzz_tunnel_test.go`: `FuzzATunnelAddressIsOneHostOrRefused` | Whatever the input, the tunnel address check refuses it or returns exactly the one address it was given. |
| A Host on this machine gets the same walls | `local_host_linux_test.go`: `TestAUnixRedeemURLCannotPointAtATCPAddress` | Every network spelling of a redeem URL (a host and port, `localhost`, user info, another scheme, a relative, unclean or query-carrying path) is refused before the token is read; a TCP listener at the named address gets no connection and no file is written. |
| | `local_host_linux_test.go`: `TestAUnixPairingPinsTheHostsCA` | A `--replace` whose answer brings another CA is refused and changes nothing; an operator certificate the CA did not sign, a lane socket or runs directory outside the shared directory, or an answer that is not transport `unix` saves nothing; a platform `--replace` of the pairing is refused before the platform is called. |
| | `local_host_linux_test.go`: `TestTheUnixLaneRefusesAPeerWithoutThePinnedCA` | A lane server whose certificate another CA signed, or that names another host, is dialled and receives no request. |
| | `local_host_linux_test.go`: `TestTheUnixLaneCarriesTheBearerAndTheSameProtocol` | A pairing with no bearer does not start and dials nothing. With one, the heartbeat and the first frame of every worker carry it; the pools are the tunnel's (two parked harness workers) and a parked worker serves a harness job over the socket. |
| | `local_host_linux_test.go`: `TestTheCoderGrantRuleAppliesToAUnixPairing` | On an anchored machine a run-up over the unix lane without the standing coder grant is refused at the gate; with the approved grant it passes. |
| | `local_host_linux_test.go`: `TestARunSocketIsTheOwningPairingsOnly` | The owner's run is a 0660 socket in the owner's runs directory, given to the `privatae-host` group, and reaches the run's control socket; another pairing's directory never gets it, another pairing cannot open it, and once the run is not the pairing's a connection gets nothing and the socket goes. |
| | `local_host_linux_test.go`: `TestARunSocketGoesAtRunDownAndAtTheWatchdogsStop` | The socket is removed at run-down and at the watchdog's stop and does not come back; with no `privatae-host` group it is root's and the reason is logged. |
| | `local_host_linux_test.go`: `TestARunsDirectoryTheHostCanChangeGetsNoSocket` | A runs directory the Host owns, a group-writable one, one under a directory the Host owns, or one in a shared directory that is not sticky gets no socket, and a link swapped in for the socket between bind and chmod changes nothing; the design's layout (1770 shared directory, `runs/` made by the bastion) gets its socket. |
| | `local_host_linux_test.go`: `TestARunSocketOpensOnlyForALiveRunOfThePairing` | No socket is made for a run with no record, another pairing's run or a run the watchdog stopped; another pairing reusing the run_id gets its own. |
| | `local_host_linux_test.go`: `TestAUnixPairingsRunStillCannotReachThisMachine` | A run a unix pairing owns gets 403 from its egress proxy for loopback, this machine's public address and a name for it. |
| | `local_host_linux_test.go`: `TestTheOwnersImagePrefix`, `TestALocalImageRunsByItsIDWithoutAPull` | Run-up takes only `<prefix>harness-<engine>@sha256:<digest>` under the owner's prefix, and pull credentials only for its registry. A local image runs by its ID with no pull only when the image with that ID carries a tag of the named repository. |
| No MCP endpoint | `claims_static_test.go`: `TestNoRouteOpOrDependencySpeaksMCP` | Every HTTP route on every listener is in a fixed table and none names MCP; no management op, import, module or string in the code names MCP, an `/mcp` path or JSON-RPC. |
| Grants are verified here | `anchor_test.go`: `TestPairingGrantSyncWalls` | A pairing grant signed by another key, for another machine, naming another anchor, or expired is refused, and the pairing stays pending. |
| | `fuzz_grants_test.go`: `FuzzAChangedSignedByteNeverVerifies` | For every kind of signed record, changing any byte of the record or its signature makes it fail to verify. |
| | `session_test.go`: `TestSessionPinsTheHostKeyWithoutAStoreGrant` | The first key offered is pinned; a different key later is refused and the pin is kept. |
| | `anchor_test.go`: `TestAnchorVerifyKeyPinsFromDCNAndRefusesRepin` | The anchor's verify key cannot be re-pinned to a different key. |
| | `session_test.go`: `TestSessionRefusedWithoutGrantIs126` | An op the grant both allows and denies, or a grant that denies `*`, is refused. |
| | `localdeny_test.go`: `TestTheLocalSwitchCanOnlyEverRemoveReach` | Switching a capability off on this machine never turns a refusal into an allow. |
| Fixed argv | `observe_ops_test.go`: `TestObserveArgsNeverReachArgv` | Shell metacharacters and flags sent as arguments to every observe op are refused or never reach a command line, and each op runs only its pinned argv. Linux only. |
| | `contextextract_test.go`: `TestCtxExtractRefusesAnUnknownTool` | Text extraction runs only tool names from its fixed table. |
| | `claims_unix_test.go`: `TestTheAllowlistedOpIgnoresTheCallersArguments` | `uptime`, sent through the management lane with hostile arguments, runs its program with none. |
| | `claims_static_test.go`: `TestTheAllowlistedOpRunsItsTableArgvOnly` | The allowlisted table is exactly `uptime` with no arguments, and the one command the lane starts is built from the table's argv alone. |
| | `claims_static_test.go`: `TestFileHandlersStartNoShell` | Nothing a context, store or backup handler can reach runs a shell; the one process any of them can start is the local search agent's Python, which `dcn_grant_sync` brings up. |
| Approval on the machine, once enrolled | `stepup_test.go`: `TestStepupVerifyBurnAndApprovals` | With no factor enrolled the gate passes; once enrolled, a code is used once, and an approval passes only for the exact terms it was issued for, and only once. |
| | `modelswap_test.go`: `TestAnApprovalIsSingleUse` | A spent approval does not fund a second model download. |
| | `modelswap_test.go`: `TestUnenrolledMachineCannotHaveAModelPulled` | With no factor enrolled, a model pull is refused. |
| | `session_test.go`: `TestSessionRootRefusedWithoutStepup` | A root session with no approval is refused and leaves no transcript. |
| | `session_test.go`: `TestSessionRootApprovalBindsToSession` | The purpose a root approval is bound to differs between two session ids on the same machine. Compared as strings, not through the terminal handler. |
| | not covered by a test | That a root approval's purpose also names the machine (`session.go`, `purposeForSessionRoot`). |
| On an anchored machine, a write needs an approval | `hostops_test.go`: `TestAnAnchoredBoxRefusesAWriteWithoutApprovalAndRunsItOnceWithOne` | With no factor and no device a write is refused; with a device, a write without an approval is refused, an approved one runs once, and a replay is refused. |
| | `hostops_test.go`: `TestEveryBrokenDeviceApprovalIsRefused` | A device approval for other arguments, with a changed signature, expired, for two uses or with no nonce is refused. |
| | `hostops_test.go`: `TestAConsoleApprovalRunsAWriteOnce` | An approval given with the factor enrolled here runs the write once. |
| | `hostops_test.go`: `TestEveryOpIsReadOrWrite` | Every op on the management lane is classified as a read or a write, and a new op counts as a write. |
| | `hostops_test.go`: `TestRepeatedRefusedWritesQuarantineThePairing` | After repeated refused writes the pairing's writes are held, even approved ones; reads and revokes still pass. |
| | `claims_update_forward_test.go`: `TestANewerSignedReleaseNeedsNoApproval` | A self-update to a newer version reaches the signed manifest with no approval; a member host's directive and the local switch still refuse it. |
| | `claims_update_forward_test.go`: `TestTheBoxTellsTheHostAForwardUpdateNeedsNoApproval` | The enforcing report says so, so the host does not ask anyone for a forward update; a build that cannot read its own version says it does not. |
| | `claims_update_forward_test.go`: `TestAnOlderOrUncomparableVersionStillNeedsAnApproval` | A self-update to an older version, the running version spelled differently, a suffixed version, or any version on a build that cannot compare its own is refused without an approval, and the host is told why; with one, a move to an older version proceeds. |
| Host-written programs run sandboxed first | `ops_test.go`: `TestOpThatWritesOutsideItsEffectsIsRefusedBeforeAnyoneIsAsked` | A dry run that writes outside its declared effects, links out of them, or writes to `/etc` is refused and lands nothing; inside the sandbox the network and `/proc` are closed. Skipped where the sandbox is unavailable. |
| | `ops_linux_test.go`: `TestOpDryRunShowsTheChangeAndApplyCommitsExactlyThat` | A dry run commits nothing; an apply must name the dry run's change list and carry an approval bound to that op, its parameters, the machine and that change list. Skipped where the sandbox is unavailable. |
| | `ops_test.go`: `TestOpTermsMutationsAreEachRefused` | Each altered field of signed op terms is refused. |
| | `ops_linux_test.go`: `TestOpSandboxShowsOnlyTheBaseAndWhatTheOpDeclared` | In a real sandbox, an op reads the file it declared and the system base; a file beside its own folder, a folder beside it and `/etc/shadow` read as empty; a declared path that has since become a link onto `/etc/ssh` refuses the run. Skipped where the sandbox cannot run. |
| | `ops_view_test.go`: `TestOpSensitivePathsAreRefusedAtUnderOrAboveAndThroughLinks` | A declared path at, under or above a credential store, as written or through a link, is refused; a malformed `sensitive_paths` refuses every op. |
| | `fuzz_paths_unix_test.go`: `FuzzAnOpEffectNeverCoversTheMachinesOwnRecord` | No accepted effect covers the bastion's own records or the system directories the sandbox masks. |
| An action op's program reaches only what it declared | `ops_action_linux_test.go`: `TestActionProgramReachesOnlyItsDestinations` | In a real unit, an apply reaches its declared destination by name; another port on that address, the declared port on another address, this machine's loopback and the internet are refused. A dry run reaches nothing, its declared destination included, and a name that resolves to the metadata service is refused. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestActionProgramSeesNothingItWasNotGiven` | In a real unit, the program runs as a fresh uid with no capabilities and no new privileges; `/root`, `/etc/shadow`, the docker and systemd sockets and an abstract socket outside it are out of reach; it reads its declared file and writes to `/tmp`, but not to the machine: not `/usr/local`, not a world-writable folder it declared as a read. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestActionCredentialIsHandedAndNothingIsLeft` | A sealed credential reaches the program and never its output; after the run no file holds it, the run's tmpfs is unmounted, its work folder and unit are gone, and no process of its uid is left, a detached one included. A dry run handed a credential is refused. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestActionBuilderSocketOnlyInApply` | The builder socket reaches the program in an apply through the socket's group, never in a dry run; a socket in root's group, or a machine with no builder, refuses an apply that builds. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestActionVerbCredentialNeverReachesTheRealProgram` | In a real unit, a credential a `tree.checkout` names never reaches the program, while the verb uses it and the program's own credential is handed and scrubbed from its output. Skipped where action ops cannot run. |
| An action op is never capped, and yields first | `ops_action_linux_test.go`: `TestActionMemoryIsNotCappedAndTheOpYieldsFirst` | In a real unit, a run holds 1500 MiB resident with nothing limiting it, and the kernel would kill it first (`oom_score_adj` 1000). When the machine's free memory falls to the floor, the op is stopped, with a refusal that names its peak. A machine already under the floor starts no op and spends no uid. Skipped where action ops cannot run or 10 GiB is not free. |
| | `ops_action_linux_test.go`: `TestActionYieldsWhenTheServicesWaitOnMemoryNotForItsOwnStalls` | Against a stand-in tree of pressures: neither the op's own slice waiting nor a pod group already waiting stops it; the services' slice rising to 12.5% during the run stops it within seconds; a group that stays at a level does not stop the next run; a group that spiked as the run began and fell back does not hide a later rise. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestActionProgramSeesNothingItWasNotGiven` | (also) The real unit's program sits in `privatae_ops.slice`, the slice the pressure reading leaves out. |
| | `ops_action_linux_test.go`: `TestTheMemoryWatchReportsOnlyAKillThatLanded` | A kill that finds no unit is not reported as the op stopped. |
| | `ops_action_linux_test.go`: `TestTheMemoryWatchKeepsTryingUntilTheKillLands` | With the machine short before the op's unit exists, the first kill finds nothing; the real unit that starts a second later is still stopped. Skipped where action ops cannot run. |
| | `ops_action_linux_test.go`: `TestMemoryFloorSitsAboveTheKubeletsEviction` | The floor reads the kubelet's eviction line from the k3s config, its drop-ins, the k3s unit's flags, the kubelet config k3s writes, and any kubelet config file or folder a flag names (one named and missing counts as unreadable): percentages, decimals, binary and decimal units, soft as well as hard, and a kubelet config file's form, never a comment. It sits 512 MiB above that line, or at 5% of memory, or at 1 GiB, whichever is largest. A value it cannot read raises the floor to 10% plus 512 MiB. |
| | `ops_action_linux_test.go`: `TestActionApplyOfAnotherChangeListRunsNothing` | An apply whose change list differs from the approved one is refused before the program starts. Skipped where action ops cannot run. |
| | `ops_action_test.go`: `TestActionManifestRefusesWhatIsNotDeclaredOrNotBounded` | An unknown verb or argument, a workload, container, unit or tree named by a parameter, an undeclared credential, verbs without root, a destination on loopback, link-local or a metadata service (also inside NAT64 or IPv4-mapped IPv6), the bastion's own unit, a tree on a credential store, a tree or container moved twice by one op, and more, are each refused when the op arrives. |
| | `ops_action_test.go`: `TestSealedCredentialsOpenOnlyForThisRunAndThisOp` | A credential sealed for another run, to another machine, tampered, expired, undeclared, missing or sent twice is refused. |
| Root verbs move only forward | `ops_verbs_linux_test.go`: `TestSetImageTouchesOnlyTheNamedContainerAndOnlyForward` | Against a stand-in kubectl: a digest with no receipt, a receipt from another repository, a container the workload lacks, a live image this machine never rolled (a receipt for it included), another image and a backward commit are each refused with nothing set; a forward roll sets exactly the named container and records it; an image already set still waits for its rollout, and fails when it does not finish. The ancestry answer is a stand-in here. |
| | `ops_verbs_linux_test.go`: `TestAncestryByFetchRefusesABackwardOrSidewaysCommit` | With real git, the ancestry check `k8s.set_image` makes accepts a forward commit or the same one, and refuses a backward, sideways or unknown commit. |
| | `ops_verbs_linux_test.go`: `TestTreeCheckoutMovesOnlyForward` | With real git: a tree moves forward to the exact commit, runs none of its own hooks, leaves untracked files and nested repositories alone, and refuses a backward or sideways commit, another origin, local changes and a config that could run a program. |
| | `ops_verbs_linux_test.go`: `TestTreeCheckoutRefusesATreeRootDoesNotControlAndKeepsIgnoredFiles` | A tree, `.git` or anything in it another user owns, or a git config anyone or another group can write, is refused before git runs; a move that would overwrite an ignored file the machine keeps is refused and the file is untouched. |
| | `ops_verbs_linux_test.go`: `TestTreeCheckoutNeverWritesIntoAFolderRootDoesNotControl` | A move that would write into a folder another user owns is refused and writes nothing; a move that leaves that folder alone goes ahead. |
| | `ops_action_test.go`: `TestReceiptsAreThisMachinesAndBindTheCommit` | A receipt this machine signed names the commit behind a digest and never makes it look rolled; the first receipt for a digest stands and a conflicting one is refused; a changed, relabelled or foreign receipt is refused. |
| A ship plan runs as your device signed it, and only there | `ops_plan_test.go`: `TestAMachineRefusesEveryPlanItShouldNot` | A machine refuses a plan whose line, params, commit, expiry or code flag was changed after signing; a line for another machine; a plan naming another key for this machine; a device it never pinned; a line whose input receipt is missing, foreign, from another plan or of a failed step; an expired plan; a line run twice; and a plan older than one it already ran. |
| | `ops_plan_test.go`: `TestTheDeviceSignsOnlyAPlanWhoseMachinesItPinned` | The device refuses a plan naming a machine it has not pinned, puts in its own pinned key for each machine whatever the pod sent, names every step in the words it shows, and signs each plan for a pipeline with a higher version. |
| | `ops_plan_test.go`: `TestARootPlanNeedsTheCodeOnTheDevice` | A plan with root work is refused without the code or with a wrong one, is signed with a right one and says so, and is never signed by "approve all shown". |
| | `ops_plan_test.go`: `TestARootLineNeedsTheCodeAndTheOpsOwnVerbs` | A root line from a plan that does not say the code was given is refused, whatever signed it; a line showing other verbs than its held op declares is refused. |
| | `ops_plan_test.go`: `TestAnUndoNeedsAFailedLaterLineOfThePlan` | An undo is refused for a step the plan does not let be undone, on an earlier step's failure or any success, on a later step whose apply (not check) failed, or for a step this machine never ran; it runs once. |
| | `ops_plan_linux_test.go`: `TestAnUndoLeavesWhatMovedSinceAlone` | An undo takes a workload back only from the state the step left it in; one that moved since is left alone. |
| | `ops_plan_linux_test.go`: `TestAnUndoRestartsTheUnitOnlyAfterPuttingTheStateBack` | An undo of a step that set an image and restarted a unit sets the image back first and restarts the unit after. |
| | `ops_plan_linux_test.go`: `TestAnUndoOfATreeNeverOverwritesAnIgnoredFile` | Moving a tree back is refused when it would overwrite a file the machine keeps and git ignores, each name matched as itself, never as a pattern or pathspec; the file is untouched. |
| | `ops_plan_linux_test.go`: `TestALineRunsOneAttemptAtATime` | In real units: a second attempt of a step is refused while the first runs, and once one passed none runs again. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestAnUndoAfterARetryGoesBackToBeforeTheFirstAttempt` | In real units: a roll that set the image and failed, then passed on its retry, is undone by a failed check to the image live before the first attempt, and never runs again after its undo. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestOnlyTheLatestAttemptsFailureUndoesTheLine` | In real units: an earlier attempt's failure undoes nothing once a later attempt passed, or while a later attempt is the latest; the latest attempt's failure undoes to before the first. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestALaterLinesCheckUndoesOnlyOnItsLastAttempt` | In real units: a check that may still be retried undoes nothing; its last allowed attempt's failure undoes the roll. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestAVerbThatCannotBeRecordedDoesNotRun` | In real units: a verb whose record for the undo cannot be written is not run, and the step fails. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestAnAttemptTheBastionDiedInIsSettled` | An attempt whose bastion process is gone is settled at startup: as it ended, from its kept receipt, or as failed with a signed receipt saying so; an attempt of a live process is never settled. |
| | `ops_plan_linux_test.go`: `TestARetryLeavesATargetSomethingElseMovedAlone` | In real units: a retry of a roll whose workload another pipeline moved after the first attempt is refused, and the undo leaves the other change in place. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestATargetMovedWhileTheProgramRunsIsLeftAlone` | In real units: a workload another pipeline rolls while the line's program runs is not rolled over, and the undo leaves the other change in place. Skipped where action ops cannot run. |
| | `ops_plan_linux_test.go`: `TestAVerbMovesOnlyFromTheStateItWasApprovedToMoveFrom` | A roll whose workload is in another state than the one its change list read and recorded sets nothing; in that state it rolls. |
| | `ops_plan_linux_test.go`: `TestATreeMovesOnlyFromTheCommitItWasApprovedToMoveFrom` | With real git: a tree at another commit than the one its change list read does not move; at that commit it does. |
| | `ops_plan_linux_test.go`: `TestTwoChangesToOneTargetNeverInterleave` | Two rolls of one workload at once: the second waits while the first is between its read and its write, then finds the workload moved and sets nothing. |
| | `ops_plan_linux_test.go`: `TestAChangeWaitsForOneInFlightOnTheSameTarget` | A tree move, a tree undo and an image undo each wait, without reading the target, while another change holds it, and run once it is done. |
| | `ops_verbs_linux_test.go`: `TestEveryCommandAVerbRunsHasADeadline` | Every command a verb runs has a deadline (a minute; a rollout or a unit's restart six, past their own five), so one that never answers cannot hold its target's lock; a command past it is stopped. |
| | `ops_plan_linux_test.go`: `TestAnUndoReadsItsTargetAgainBeforeItWrites` | An image or tree undo reads its target again right before its write; a roll or commit made after its first read is left in place. |
| | `ops_plan_linux_test.go`: `TestOnlyAProcessKnownToBeGoneIsSettled` | An attempt is settled only when its process is known to be gone or replaced under its pid; this process, and any when /proc cannot be read, are not. |
| | `ops_plan_linux_test.go`: `TestAnUndoMatchesTheReceiptToTheLinesRecord` | An undo is refused while an attempt runs, twice, on a later step's failure when this step did not pass, on the step's own failure once an attempt passed, and on an attempt older than the latest. Called directly. |
| | `ops_plan_linux_test.go`: `TestALinesRecordAndLedgerAgreeAndAreLetGo` | An attempt spent with no record of it is refused; a step's record and receipts are let go a week after the plan expires, not before. |
| | `ops_plan_test.go`: `TestLinesRunInOrderAndOnlyAsOftenAsThePlanAllows` | A line is refused until every line before it has a successful signed receipt; a line runs only as many times as the plan allows. |
| | `ops_plan_test.go`: `TestAPlanCarriesNothingThatCouldHideWhatThePersonReads` | The device refuses a plan whose input, params or verbs hold an escape, a line break, a direction mark, a key twice, an unknown verb or argument; its words carry no control character. |
| | `ops_plan_test.go`: `TestThePageAsksTheCodeForARootPlanAndNeverApprovesItWithAll` | The approvals page asks for the code on a root plan's card, leaves it out of "approve all shown" even when its id is posted, refuses it without the code and signs it with it. |
| | `ops_plan_linux_test.go`: `TestAShipPlanRunsEachLineOnceAndUndoesOnAFailedCheck` | In real units against a stand-in kubectl: a build's receipt carries its digest; the roll refuses to run before it and then rolls exactly that digest, adopting the live image as the first roll; a replay is refused; a failed check undoes the roll to the image live before; a plan whose roll names a digest none of its steps built rolls nothing. Skipped where action ops cannot run. |
| A server in the service slot has no network | `service_test.go`: `TestServiceUpRunsAStayingContainerWithNoPublishedPort` | The container starts with `--network none`, all capabilities dropped, no new privileges and no published port. |
| | `service_reach_test.go`: `TestReachGrantSyncAndTheForwardWall` | Installing a reach grant is refused without an approval, for another host, or for another machine. The reach check then admits the granted host to the granted server only, and a revoked grant admits nothing. Called directly, not through the slot listener. |
| | `claims_unix_test.go`: `TestTheServiceSlotAdmitsOnlyWithTheFamilyAndAReachGrant` | Through the slot listener: each connection is checked, and one without a reach grant for that server, or without the `services` family, never reaches the server's socket. |
| | not covered by a test | The reach check's own comparison of a stored grant's machine. |
| Egress for someone else reaches the public internet, never this machine | `coders_linux_test.go`: `TestCoderEgressRefusesEveryInternalClass` | A coder run's proxy refuses every internal class (loopback, RFC 1918, CGNAT, link-local and metadata, ULA, IPv4-mapped, IPv4-compatible, IPv4-translated, NAT64, 6to4, unspecified, 0/8, 198.18/15, 240/4, multicast, fec0::/10), by address and by a name with one such answer among public ones, and `localhost` names and names that do not resolve. |
| | `coders_linux_test.go`: `TestCoderEgressRefusesThisMachinesOwnPublicAddress` | A public address on this machine's interface is refused in every spelling (IPv4-mapped, NAT64, 6to4) and through a name; a neighbour on the same subnet passes; `allow_lan` is the one exception. |
| | `coders_linux_test.go`: `TestCoderEgressLocalAddressesAreReread` | An address the machine gains after start is refused; interfaces that cannot be read refuse. |
| | `coders_linux_test.go`: `TestCoderEgressDialsTheVettedAddressAndHonoursAllowLAN` | The proxy returns the vetted addresses, IPv4 first, never the name; a LAN host passes only when named in `allow_lan`, and an entry with a port only on that port. |
| | `coders_linux_test.go`: `TestCoderEgressProxyOverTheSocket` | Through the run's socket: loopback, LAN, metadata, private and this machine's public address get 403 with the reason, over CONNECT and plain HTTP; a public destination is spliced, and only its vetted address is dialled. |
| | `ownaddr_test.go`: `TestOwnDestinationAsksTheKernel` | With the kernel's answer supplied: an address a `local` route delivers here is this machine, also as the IPv4 address inside an IPv4-mapped, NAT64 or 6to4 address; a unicast route or no route is not; a failed lookup cannot decide; without a lookup the interface addresses still decide. |
| | `ownaddr_test.go`: `TestCoderEgressRefusesAnAddressTheKernelDeliversHere` | A coder run is refused an address the kernel delivers here, in every spelling, and refused anything when the lookup fails; `allow_lan` stays the exception. |
| | `ownaddr_netns_linux_test.go`: `TestAnyIPDestinationsAreRefusedInARealNamespace` | In a private network namespace with `local 192.0.2.0/24` and `local 2001:db8:a::/64` on `lo`, plus a broadcast route (198.51.101.255), anycast routes (198.51.102.0/24, 2001:db8:d::/64) and a multicast route: the real route lookup reads each as this machine, and a unicast route or no route as not; a 0.0.0.0 listener answers on both local ranges. A coder run's proxy and the anchored egress lane each refuse those addresses (local, broadcast and anycast), the IPv4-mapped and NAT64 forms of each IPv4 one, and a name resolving to each, with the lane's this-machine reason (a name the lane could not resolve does not count), and pass the unicast and no-route addresses and a name resolving to each, dialling the vetted address; each answers 403 end to end with a real dialer, the proxy over its socket and the anchored lane through its connection handler as the anchor host, to CONNECT by address and by name and to plain HTTP. The backup lanes' URL check refuses the same addresses, forms and names as this machine's or its network's and passes the unicast and no-route ones, and their dial wall refuses the local, broadcast and anycast addresses. Nothing reaches the listener. Skipped where a namespace cannot be made. |
| | `ownaddr_netns_linux_test.go`: `TestOnlyAUnicastRouteLeavesThisMachine` | The kernel's route type is read so that only unicast leaves this machine; local, broadcast, anycast, multicast, unspec, nat and xresolve are this machine. |
| | `hostops_test.go`: `TestAnchoredEgressRefusesLoopbackAndPrivateDestinations` | On an anchored machine the egress lane refuses loopback, `localhost`, private, ULA, link-local, CGNAT and metadata addresses, dials the vetted address, and a local machine keeps the lane it had. |
| | `ownaddr_test.go`: `TestAnchoredEgressRefusesThisMachinesOwnAddresses` | On an anchored machine the egress lane refuses an address on this machine's interface and one a `local` route delivers here, in every spelling, and refuses when the lookup fails; a neighbour passes; a local machine's lane is unchanged. |
| | `ownaddr_test.go`: `TestBackupLanesRefuseThisMachinesOwnAddresses` | The backup lanes' URL check refuses an address on this machine's interface and one a `local` route delivers here, in every spelling and through a name, and their dial wall refuses those addresses; a failed lookup refuses both; a neighbour on the subnet passes. With the kernel's answer supplied. |
| | `backupfetch_test.go`: `TestBackupWallJudgesTheIPv4InsideAndTheReservedRanges` | The backup lanes' classifier, address wall and URL check refuse 10.0.0.1 and 127.0.0.1 inside NAT64, 10.0.0.1 inside 6to4 and in the IPv4-compatible and IPv4-translated forms, the metadata address inside 6to4, a local-use NAT64 address, `fec0::1`, `198.18.0.0/15` (also inside an IPv4-mapped address), `240.0.0.0/4` (also inside NAT64) and `255.255.255.255`; public addresses in the NAT64, 6to4 and IPv4-mapped forms, and the addresses either side of `198.18.0.0/15`, pass the classifier. |
| | not covered by a test | A public address that reaches this machine only through a 1:1 NAT in front of it. Nothing refuses it. |
| A terminal is checked here and logged | `session_test.go`: `TestSessionOpensWithoutAGrantOnALocalBox` | On a local machine a terminal with no grant and no approval opens and is audited. The same test calls `sessionPinOfferedKey` directly: the first key offered is pinned and a different one is refused. |
| | `session_test.go`: `TestSessionRefusedWithoutGrantIs126` | A grant that is sent is verified: a bad signature, an op not listed, or an op the grant denies is refused and audited. |
| | `fuzz_grants_test.go`: `FuzzEachOpIsAllowedOnlyByItsOwnFamily` | On an anchored machine the family check (`capsAllow`) lets a host other than the anchor run an op, the session ops included, only if its pairing grant names that op's family. Called directly, not through the terminal handler. |
| | `session_test.go`: `TestSessionOnAnAnchoredBoxTheApprovalIsTheWall` | On an anchored machine a terminal without an approval is refused, with or without a factor enrolled, is audited and leaves no transcript. |
| | `session_test.go`: `TestSessionRootRefusedWithoutStepup` | A root terminal with no approval is refused and leaves no transcript. |
| | `session_test.go`: `TestSessionRootApprovalBindsToSession` | The purpose a root approval is bound to differs between two session ids on the same machine. Compared as strings, not through the terminal handler. |
| | `session_test.go`: `TestSessionFramingResizeAndTranscript` | An opened session writes a transcript and start and stop lines to the audit log. |
| | `hostops_test.go`: `TestTheDeviceSignsOnlyWhatItDerivedItself` | The approval device refuses to take a root-terminal ask. |
| Root commands run only under a grant given here with the code | `rootexec_test.go`: `TestRootExecGrantCeremony` | The grant exists only after a code from the factor enrolled here checks out, once per code, with an expiry no longer than a year; past its expiry or after a revoke it refuses. |
| | `rootexec_test.go`: `TestRootExecRefusals` | Through the terminal handler: with no grant, an expired, revoked, other-host or other-machine grant, from a member pairing holding the `session` family, or with the bastion not root, the command is refused, never starts, leaves no transcript and is audited with its command. |
| | `rootexec_test.go`: `TestRootExecLocalSwitchRefuses` | With `session` switched off here, a granted command is refused. |
| | `rootexec_test.go`: `TestRootExecRoundTrip` | A granted command returns its stdout, stderr and exit status, and is written to a transcript and to the audit log at start and stop with the command. |
| | `rootexec_test.go`: `TestRootExecOutputCapIsStated` | An output over the cap keeps its first and last half, says how many bytes were cut, and is kept whole in the transcript. |
| | `rootexec_test.go`: `TestRootExecDeadlineKills` | A command past its deadline is killed and answered with 124 and timed_out. |
| | `rootexec_test.go`: `TestRootExecStopsWhenAWallFallsMidRun` | Through the handler: a command already running is killed within one recheck when its grant is revoked or expires, `session` is switched off here, or the pairing is quarantined, and answered with 126 and a J that says why; while every wall holds, the recheck leaves it alone. |
| | `rootexec_test.go`: `TestRootExecDeadlineKillsAChildThatIgnoresSIGTERM` | Through the handler with the real `/bin/sh`: at the deadline a child that ignores SIGTERM, holding the output open or not, is gone when the answer arrives, within the deadline and the kill grace. Every signal goes through a fence that admits only the process group the test started. |
| | `rootexec_test.go`: `TestRootExecBadCommandAndTranscriptFailureAreAudited` | A bad command, a bad session id, and a transcript that cannot be opened each leave an audit row with the command (or its size and sha256) and exit 1; none starts. |
| | `rootexec_watch_linux_test.go`: `TestRootExecWatchKernel` | In a private network namespace, through the handler with the real `/bin/sh`, nftables and a cgroup: a command's connections to outside addresses (IPv4 and IPv6, TCP and UDP) are reported in `untrusted_connections`; loopback, the machine's own address and listed platform ranges are not, though they stay in the audit row marked own; a grandchild's connections are caught; what a command reached before its deadline killed it is reported; no table or cgroup is left after any of them, and one left by a dead bastion is removed by the next sweep, with any process in it moved to its parent. |
| | `rootexec_watch_test.go`: `TestRootExecJCarriesOnlyOutsideConnections` | The J frame lists only the destinations outside the platform list (addresses, CIDRs and resolved names), the stop row lists every one and counts the outside ones, the transcript records them; with only loopback and own hosts the field is absent. |
| | `rootexec_watch_test.go`: `TestRootExecUnwatchedCountsAsOutside` | A command whose connections could not be watched is reported with one untrusted entry that says why. |
| | `rootexec_watch_test.go`: `TestRootExecOwnHostsList` | No list means only loopback is own; a broken list or a bad entry reads as empty; a name that does not resolve adds nothing; the host's list is capped and the rest counted. |
| | `claims_unix_test.go`: `TestAMemberWithoutTheSessionFamilyGetsNoTerminal` | Through the terminal handler, on an anchored machine: a host other than the anchor without the `session` family is refused and leaves no transcript; once the family is granted the same approval opens the terminal. |
| | `claims_unix_test.go`: `TestAnAnchoredTerminalApprovalOpensOneSessionOnce` | Through the handler: an anchored machine's terminal approval is refused for another session, opens its own, and is refused when used again. |
| | `claims_unix_test.go`: `TestARootTerminalNeedsTheBastionToRunAsRoot` | Through the handler: with a factor enrolled and an approval for that session, a bastion not running as root refuses a root terminal, and the same approval opens it once the bastion runs as root. |
| | `claims_unix_test.go`: `TestADeviceCannotApproveARootTerminal` | Through the handler: this machine refuses a device approval for a root terminal, with or without a factor enrolled. |
| | `claims_unix_test.go`: `TestARootApprovalOpensOneSessionOnce` | Through the handler: a root approval is refused for another session, opens its own, and is refused when used again. |
| | `claims_unix_test.go`: `TestTheSessionHandlerPinsTheOfferedKey` | Through the handler: the first key a frame offers is pinned, and a later frame offering another key is refused with the pin kept. |
| | not covered by a test | That a root approval's purpose names the machine (`session.go`, `purposeForSessionRoot`). |
| Root only where there is no one else to ask | `anchor_test.go`: `TestClaimAnchorWalls` | `claim-anchor` is refused without machine authority. Asserted only when the tests run without root. |
| | `owner_test.go`: `TestClaimOwner` | `claim-owner` is refused without root and writes nothing. Asserted only when the tests run without root. |
| | `claims_unix_test.go`: `TestMachineWideFactsNeedMachineAuthority` | `claim-owner`, `claim-anchor`, `claim-anchor --repin` and `set-mode networked` are refused without machine authority and write nothing; with it, each completes (`--repin` re-pins the anchor to the pairing that holds it). Both halves run whatever user the tests run as. |
| On macOS and Windows, a networked bastion is the system's service | `sysservice_test.go`: `TestLaunchdPlistRunsTheDaemonAsRootAtBootAndKeepsItAlive` | The launchd job is well-formed and runs the program as root at boot, with root's home, and launchd restarts it whenever it exits. |
| | `sysservice_test.go`: `TestBinaryChainMustBeRootOnly` | On macOS the service is refused for a program a non-root user owns, that a group or everyone can write, that is a symlink, or that sits under such a directory. Run against a stand-in for the disk, not on a Mac. |
| | `sysservice_test.go`: `TestWindowsServiceBinaryMustLiveUnderProgramFiles` | On Windows the service is refused for a program outside Program Files, including the per-user install folder. |
| | `sysservice_test.go`: `TestServiceGuardRefusesAUserspaceBastionBesideTheService` | With the service installed, `pair`, `run` and `status` from an account without machine authority are refused; an administrator, and a machine with no service, are not. |
| | `sysservice_test.go`: `TestServiceModeOpensNothingOnTheDesktop` | As a Windows service, the tray, the blocking dialog and the detached relaunch after an update each return before doing anything. Read from the source, not run. |
| | `runlock_unix_test.go`: `TestARunBesideTheMacServiceIsRefusedBeforeItStarts` | With the macOS daemon installed, a second `run` is refused while the first holds the lock in the state folder, and may run once it is gone; with no daemon nothing is locked. Run against the real lock on Linux; the macOS wiring (`runguard_darwin.go`) is not run off a Mac. |
| | not covered by a test | That launchd and the Windows service manager actually restart the bastion after it exits (`sysservice_darwin.go`, `sysservice_windows.go`); neither runs off its own platform. |
| | `freeagent_drop_winrules_test.go`: `TestFaWinOwnerRefusalRunsOnlyAsAPerson` | On a Windows service a folder's agent is refused when the folder's owner is SYSTEM, a service account, a BUILTIN group such as Administrators, the built-in Administrator or Guest, or not a person's account; a local, domain or Entra ID user is accepted. |
| | `freeagent_drop_winrules_test.go`: `TestFaAgentDirStaysOutOfTheFolderWhereTheHandOverIsAPermission` | Where the hand-over is a permission entry (Windows), the agent's directory is never made inside the person's folder. |
| | not covered by a test | That the Windows agent is started under the owner's session token, and that its state leaf's permission is set only while the leaf is empty (`freeagent_drop_windows.go`); neither runs off Windows. |
| Observation changes nothing on the machine | `observe_endpoints_test.go`: `TestObserveEndpointAllowedIsTheInverseOfObserveNet` | The monitoring ops may reach only private addresses, exactly the ones `observe:net` refuses. |
| | `observe_endpoints_test.go`: `TestObserveDialControlRefusesPublicAtConnectTime` | A public address is refused at the socket, so a DNS answer cannot move a query outside. |
| | `observe_endpoints_test.go`: `TestObserveNeverFollowsARedirect` | A redirect from a monitoring endpoint is reported as a failure, and its target is never fetched. |
| | `claims_static_test.go`: `TestObserveOpsWriteNothing` | Nothing an observe or computer op can reach writes, removes, renames, changes permissions on, mounts or signals anything, apart from the bastion's own audit line and its journal of observe results; the programs those ops run are a fixed list of reads. |
| | `claims_static_test.go`: `TestNoInputInjection` | No input-injection program is run, no Windows input API is loaded, and no script the computer ops run asks for a keystroke, a click or an accessibility action. |
| A backup's key goes to a host only when you approve it here | `backupreseal_test.go`: `TestBackupResealWaitsForThePersonThenDeliversToTheHostOnly` | Through the management lane: a request is filed pending and hands out nothing; another pairing cannot read it; after approval here the host receives the record sealed to its key only; a refusal hands over nothing; a decided request cannot be decided again. |
| | `backupreseal_test.go`: `TestResealOpensAnAgeWrittenSidecarAndSealsToTheHostAlone` | A sidecar written by the age command is resealed byte for byte to the host's key alone (not to the key that opened it, not to another host), and the age command opens the result. |
| | `backupreseal_test.go`: `TestResealRefusesWhatIsNotTheBackupItClaims` | A sidecar of another kind or version, naming another backup, with a malformed stamp or key, sealed to someone else, or oversized, is refused. |
| | `backupreseal_bind_test.go`: `TestResealRefusesAnotherHostsBackupWhateverTheHostSays` | A host holding another host's key file, calling itself that host, is refused when the person approves, and nothing is sealed to it; the other host asking for its own backup is served. |
| | `backupreseal_bind_test.go`: `TestResealDecideRefusesWhatIsNotThePairingsOwn` | The refusal is in the act itself, not only the preview: a request is bound to the pairing and host number that filed it. |
| | `backupreseal_test.go`: `TestResealTakesBothPlacesABackupIsKept` | A key file naming `b/<stamp>` or `s/<stamp>` opens and is resealed to the host's key, written by this code and, where the age command is installed, by it. |
| | `backupreseal_test.go`: `TestResealRefusesAnObjectOutsideBothPlaces` | A key file naming any other folder, a path that climbs or nests, or another backup's name is refused. |
| | `backuppush_test.go`: `TestBackupPushStartRefuses` | `backup_push` refuses, before any job starts, a path outside the backup folder, a subfolder, a path through a linked folder, a link, a file not named like a backup, a folder not shared with the host, plain http, and this machine's or its network's addresses. |
| | `backuppush_test.go`: `TestBackupPushSendsNothingWhenTheFileIsNotTheOneNamed` | A file whose SHA-256 is not the one the host named fails the job before a byte is sent. |
| | `backuppush_headers_test.go`: `TestBackupPushSendsTheSignedHeaders` | The headers an upload address was signed with go on the PUT: a storage that refuses a PUT without `If-None-Match: *` accepts it, and refuses a second one with 412, reported as such. |
| | `backuppush_headers_test.go`: `TestBackupPushStartTakesTheHeaders` | Through the management lane, `If-None-Match: *` (as sent, or in lower case) is the only header a host may hand over: any other name (an unexpected header, Host, Content-Length, Transfer-Encoding, Connection), any other value for it, or a split header line is refused before a job starts, and so is a start with no headers. |
| | `backuppush_bound_test.go`: `TestAPushFromAFolderThatStopsAnsweringFails` | A push whose file read never returns, while checking the digest or while sending, fails within the bound with a sentence instead of staying pending. |
| | `backuppush_stuck_test.go`: `TestRepeatedPushesFromADeadFolderHoldOneRead` | Pushes started again and again on a folder whose read never returns leave one blocked read, one open descriptor and no more goroutines; each start after the first stuck read is refused with a sentence. |
| | `backuppush_stuck_test.go`: `TestAPushFolderIsReadAgainWhenItsReadReturns` | Once a stuck read returns, its folder is read again: the next push there reads its file to the end. |
| | `backuppush_stuck_test.go`: `TestStuckPushReadsAreCappedPerBastion` | Across folders the blocked reads never pass the cap, and a start while the cap is held is refused, even from a folder that answers; once the reads return, a push starts. |
| | `backuppush_stuck_test.go`: `TestAPushWaitingForASlotIsNotBlamedOnItsOwnFolder` | A push from a folder that answers, waiting for a slot while other folders' stuck reads hold the cap, fails with the sentence about the cap, not one saying its own folder stopped answering. |
| | `backupreads_test.go`: `TestAPushIsNotStartedInAFolderWhoseHashingReadIsStuck` | A folder whose read for a digest has not returned refuses a push with a sentence and starts no push read there; once the read returns its digest is kept and a push starts. |
| | `backupreads_test.go`: `TestTheHashingDoesNotReadAFolderWhosePushReadIsStuck` | A folder whose push read has not returned is not read for digests, while other folders are; once it returns the folder is read again. |
| | `backupreads_test.go`: `TestStuckHashingAndPushReadsShareTheCap` | A stuck digest read and a stuck push read count toward one cap: at the cap, a folder that answers gets neither a push nor a digest read until one of them returns. |
| | `backuphash_progress_test.go`: `TestASlowHashThatKeepsAnsweringRefusesNoPushFromItsFolder` | A backup read for its digest far longer than the bound, its reads returning all along, does not make its folder stuck: a push of another backup there starts and reads its file while the digest is still being read. |
| | `backuphash_progress_test.go`: `TestAHashWithNoAnswerForTheBoundStillMarksItsFolderStuck` | A read for a digest that answers for a while and then goes without an answer for the bound makes its folder stuck: a push there is refused with the sentence about the digest, the read counts toward the cap, and once it answers its digest is kept and a push starts. |
| | `backuppush_test.go`: `TestBackupPushNeverFollowsARedirect` | An upload address that redirects is reported as a failure, and the redirect's target is never reached. |
| | `backupretention_test.go`: `TestRetentionIsNotSteeredByTheNamesAHostGives` | Files a host names into past days, all arriving today, do not push out the real backups of those days. |
| | `backupretention_test.go`: `TestRetentionRemovesOnlyWhatThisBastionFetched` | Thinning removes no file this bastion did not record fetching (a file you put there, one replaced since it arrived), no file not named like a backup, no link and nothing a link points to, and nothing when `.keep-all` is present. |
| | `backupreseal_test.go`: `TestBackupApproveNeedsTheEnrolledFactor` | With a second factor enrolled, approving without its code or with a wrong one opens nothing and leaves the request pending. |
| | `backuplist_test.go`: `TestBackupListShowsOnlyFoldersSharedWithThisHost` | A folder shared with one host is listed for that host only, and not once taken back. |
| | `backuphash_bound_test.go`: `TestAHashReadThatNeverReturnsHoldsUpNoOtherFolder` | A file whose read for its digest never returns holds up the digests of other folders only for the bound; nothing more is read from its folder while it is stuck; when it returns its digest is kept and the folder is read again. |
| | `backupshared_bound_test.go`: `TestASharedFolderThatDoesNotAnswerHoldsUpNothing` | A shared folder that hangs when resolved or read is left out of `backup_list` (named under `unavailable`) within the bound, and `backup_push` from it is refused within the bound; the folders that answer are served. |
| | `backupshared_bound_test.go`: `TestASharedFolderThatNowReachesTheBastionsStateIsLeftOut` | A shared folder replaced by a link to the bastion's configuration folder is not listed and not sent from. |
| | `backuproot_test.go`: `TestTheBackupFolderIsCreatedOnFirstBackupOp` | `backup_list` creates no folder; the first backup op that writes does. |
| | `backuproot_test.go`: `TestBackupRootsAreEachHostsOwn` | A backup op is refused while the host's backup folder is the same as, inside, or contains another paired host's, also through a link. |
| | `backuproot_test.go`: `TestBackupRootNeverOverlapsTheBastionsOwnState` | A backup folder that is or contains the bastion's configuration folder, keys or backup records, or sits in the configuration folder outside `backups/`, is refused, and none of them can be shared; the default folder is accepted. |
| No delete op on shared stores | `dcn_plan_test.go`: `TestDcnPlanCheckApplyVerify` | A move plan that escapes the store, targets an existing path, or touches an excluded file is refused whole; the op list carries the plan op and no `dcn_delete` or `dcn_remove`. |
| | `fuzz_paths_unix_test.go`: `FuzzMovePlanStaysInsideTheRoot` | Any move the plan check passes stays inside the store, targets a path that does not exist yet, and avoids excluded paths. |
| Verified releases | `release_sign_test.go`: `TestATamperedManifestIsRefused` | A manifest changed after signing is refused. |
| | `release_sign_test.go`: `TestAManifestSignedByAnotherKeyIsRefused` | A manifest signed by a key the build does not pin is refused. |
| | `release_sign_test.go`: `TestAnUnsignedManifestIsNotRead` | A manifest with no signature reaches neither the updater nor the local page. |
| | `freeagent_managed_test.go`: `TestFaEnsurePyzVerifiesHash` | An agent download whose SHA-256 differs from the manifest is refused and the installed agent's bytes are unchanged; afterwards, with the manifest unreachable, the installed path is still served. |
| | `release_sign_agent_test.go`: `TestAnOlderSignedAgentManifestDoesNotDowngrade` | An older agent version is neither downloaded nor installed. |
| | `claims_update_test.go`: `TestADigestMismatchNeverSwapsTheBinary` | A self-update whose download does not match the manifest's SHA-256 (another build's, empty, truncated) leaves the running binary byte-identical with nothing moved aside. |
| | `claims_update_forward_test.go`: `TestTheForwardPathInstallsNothingButTheSignedTarget` | With no approval, a signed manifest for a version other than the target, and an unsigned manifest for the target, are never downloaded from; a signed manifest naming the target is. |
| | not covered by a test | Where the release key is kept; the installer's SHA-256 check. |
| No secrets cached for git | `claims_git_test.go`: `TestTheGitHelperFetchesATokenPerAuthAndStoresNothing` | Each auth asks the daemon for a fresh token; store and erase do nothing; nothing is written to the bastion's config. |
| | `claims_git_test.go`: `TestNoHelperOnTheMachineStoresTheForgeToken` | A real git reading the forge through the proxy, with git's `store` helper configured before `git-setup`'s lines, after them, or in the repository, authenticates with the host's token and writes it nowhere. |
| | `claims_git_test.go`: `TestGitSetupResetsTheHelperChainBeforeItsOwnHelper` | `git-setup` prints the reset of the forge's helper chain right before its own helper, for one host and for several. |
| | `claims_git_test.go`: `TestWithoutTheAuthtypeCapabilityOnlyTheResetProtects` | For a git without the authtype capability the helper answers the username and password, and only a helper configured before the reset is kept out. |

`deploy/check-claims.sh` checks that every test this table cites exists in
`client-go`; run it after renaming or removing a test.

To report a security issue, please do not open a public issue. See
[SECURITY.md](SECURITY.md).

## Supported platforms

Release builds are produced for:

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 (Apple silicon) |
| Windows | amd64, arm64 |

Platform-specific observation is implemented natively on each OS. Where a
platform has no implementation for a capability, that capability is withheld
rather than faked.

## Build from source

Requires Go 1.25 or newer. The binary is pure Go and builds with `cgo` off.

```sh
git clone https://git.privatae.ai/privatae/privatae-bastion.git
cd privatae-bastion/client-go
CGO_ENABLED=0 go build -o privatae-bastion .
./privatae-bastion version
```

Every push runs the same checks in CI (`.gitea/workflows/ci.yml`).

To build a specific release rather than the latest source, check out its tag
first (`git checkout v<version>`).

Cross-compile the way the release pipeline does:

```sh
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-X main.clientVersion=dev" -o privatae-bastion-darwin-arm64 .
```

### Verify a release

Release builds are reproducible: `deploy/build.sh` pins the Go toolchain image
by digest and builds with `-trimpath`, so the same commit gives the same bytes
on any machine. To check that what we publish is what this source builds (needs
git, docker, curl and python3), run this from a clone of this repository:

```sh
deploy/verify-release.sh
```

It checks the release manifest's signature against the keys pinned in
`client-go/release_sign.go`, checks out the release's source, rebuilds it, and
compares every binary's sha256 with the published one.

From this release on, each public snapshot in this repository carries the tag
`v<version>` (for example `v0.43.0`). The manifest's `built_from` names the
commit in the repository the release was built in, which is not a commit here,
so the script checks out the tag `v<version>` for the version the manifest
names, and prints which source it used. The tag is annotated and its message
has the line `built from <built_from>`, exactly as the manifest writes it; the
script refuses a tag without that line.

The digests show this source builds the published binaries. They say nothing
about files the build does not read: those could differ without changing the
bytes.

If the published version has no tag in your clone, the script says so and
stops without building. If it cannot fetch tags, it says that instead.
Releases from 0.43.0 on can be checked this way from a clone of this
repository.

Run the tests:

```sh
go test ./...
```

The suite covers all three platforms' parsing and judgement logic from a single
`go test` on any OS, because every platform-specific decision is kept in files
with no build tag and only the enumerators are tagged.

The walls a host's input has to get through also have fuzz targets
(`client-go/fuzz_*_test.go`): the path sandbox for store reads and move
plans, an op's declared effects and path params, service slot names, which
capability family lets a pairing run an op, and every signed record and
approval the bastion verifies. Each target states the property the wall
exists for. `go test` runs their seed inputs; to let the fuzzer search for an
input that breaks one, run each target for a bounded time:

```sh
deploy/fuzz.sh        # 20 seconds per target; deploy/fuzz.sh 300 for longer
```

## Repository layout

```
client-go/        the bastion: one Go package, one binary
  main.go         CLI entry point and built-in help
  run.go          daemon: tunnel, lanes, heartbeat, control ports
  pair.go         pairing and key generation
  pair_unix.go    pairing with a Host on this machine over its enroll socket
  coder_socket.go a coder run's socket for a Host on this machine
  anchor.go       networked-mode anchor
  mgmt*.go        management lane, allowlist and audit
  writes.go       which management ops are writes (and need an approval)
  device*.go      the approval device
  quarantine.go   closing a pairing's write lanes after repeated refusals
  ops*.go         host-written ops: terms, sandbox, dry run and apply
  service*.go     service slot: servers with no network, reach grants, mirrors
  session*.go     session lane (interactive terminal)
  dcn*.go         Distributed Context Network store handlers
  context*.go     folder sharing and on-machine text extraction
  modelswap.go    model store
  inferencefilter.go  filter on the ollama forward (scoped pairings, local models switch, withheld grants)
  mirror.go       memory mirror: the host's database replica on your disk
  stepup*.go      second-factor enrolment and approvals
  agents*.go      agent observe
  freeagent*.go   the bastion agent: install, run and supervise it (see below)
  release_sign.go the release keys and the manifest signature check
  computer*.go    computer observe
  observe*.go     host observe, baseline and delta
  ui*.go          local console
  uiassets/       console HTML and CSS
deploy/
  VERSION         current release version
  install.sh      macOS / Linux installer
  install.ps1     Windows installer
  build.sh        reproducible cross-compile, shared by publish and verify
  publish.sh      release pipeline: build, sign the manifest, publish, verify
  release-sign/   the signing tool: runs where the release key is, never here
  release-verify.sh  check a manifest's signature against the pinned keys
  verify-release.sh  rebuild a published release and compare its digests
  fuzz.sh         run every fuzz target for a bounded time
  check-claims.sh  check that every test the security table cites exists
LICENSE           GNU GPL v3
```

The bastion agent (repository `bastion-agent`) was first called freeagent,
and some names keep that word on purpose. They are stable names, not
leftovers, and are not renamed:

- the Go files and identifiers above (`freeagent*.go`, `fa*`);
- the agent's state directory, `/var/lib/privatae/freeagent` on a root
  install, where each installed agent keeps its key, vault and logs;
- the heartbeat fields `freeagent_ok` and `freeagent_stores`, and the
  `freeagent` capability, which the platform reads;
- the `FREEAGENT_*` environment variables the bastion sets for the agent
  process, and the `freeagent: 1` schema field of the agent's manifest.

Renaming the directory, the fields or the variables would break an installed
machine or the platform's reader for no change in behaviour, and renaming the
code would only make its history harder to follow. The public addresses were renamed:
from 0.42.0 the bastion reads only `privatae.ai/bastion-agent/version.json`
and the `bastion-agent-<version>.pyz` it names. The legacy
`privatae.ai/freeagent/` address has been retired and no longer answers.
Bastions from 0.20.0 to 0.41.x only fell back to it, so they read the new
address. A bastion older than 0.20.0 read only the old one: it finds the
address gone and keeps the agent it has installed.

## Contributing

Sign-in on this forge is not reachable from the internet, so you cannot file
an issue or open a pull request here. You can read, clone, build and verify a
release, and fork under the GPL. Report a bug or a security problem by email
(see [SECURITY.md](SECURITY.md)).

[CONTRIBUTING.md](CONTRIBUTING.md) has the checks a change has to pass and the
principles it has to respect.

The checks every change runs:

```sh
cd client-go
go vet ./...
go test ./...
```

Keep the principles that the code already follows: the bastion dials out,
fixed argv, no shell in file handlers, approval on the machine, and
capabilities withheld rather than faked when a platform cannot deliver them.

## License

This repository is free software, licensed under the GNU General Public License
version 3 or (at your option) any later version. See [LICENSE](LICENSE).
Copyright Privatae LLC.

You may run it, read it, change it and redistribute it under that license. The
Privatae platform the bastion connects to is separate, proprietary software and
is not covered by this license.

The local console vendors [htmx](https://htmx.org) 2.0.10
(`client-go/uiassets/htmx.min.js`), which is distributed under the Zero-Clause
BSD license reproduced in `client-go/uiassets/htmx.LICENSE`. Go module
dependencies are listed in
`client-go/go.mod` and carry their own licenses.
