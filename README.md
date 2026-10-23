# privatae-bastion

[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8.svg)](client-go/go.mod)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#supported-platforms)
[![ci](https://git.privatae.ai/privatae/privatae-bastion/actions/workflows/ci.yml/badge.svg?branch=main)](https://git.privatae.ai/privatae/privatae-bastion/actions)

**One static Go binary that gives your AI Host access to a machine without SSH keys: it dials out, checks every signed grant on the machine itself, and keeps its own audit log.**

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
# A server (macOS / Linux, as root): networked, anchored to the first host you pair
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
sudo -H privatae-bastion pair <token>       # token from your host's "Set up a bastion"
sudo -H privatae-bastion stepup-enroll      # your second factor, so you can approve here

# Your own computer (macOS / Linux, as you)
curl -fsSL https://privatae.ai/bastion/install.sh | sh
privatae-bastion pair <token>
privatae-bastion run                        # tunnel + lanes up
```

```powershell
# Windows, your own computer
irm https://privatae.ai/bastion/install.ps1 | iex
privatae-bastion pair <token>
privatae-bastion run
```

A Windows server installs from an Administrator PowerShell with `-Networked`.
See [Install](#install).

**AI readers and reviewers:** [docs/README.md](docs/README.md) lists every reference page, one line each, and [docs/claims.md](docs/claims.md) is the full table of security claims and the test behind each.

**Contents:** [Why a bastion](#why-a-bastion) · [Install](#install) ·
[Quick start](#quick-start) · [Local and networked modes](#local-and-networked-modes) ·
[Replacing an agent's SSH keys](#replacing-an-agents-ssh-keys) ·
[What the bastion does](#what-the-bastion-does) · [Security model](#security-model) ·
[How each claim is tested](#how-each-claim-is-tested) ·
[How this repo is published](#how-this-repo-is-published) ·
[Supported platforms](#supported-platforms) · [Build from source](#build-from-source) ·
[Verify a release](#verify-a-release) · [Contributing](#contributing) · [License](#license)

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

There are two ways to run the bastion, and the installer picks by who runs it.

**On a server** (run the installer as root). The bastion is installed as the
machine's system service in **networked** mode (Linux with systemd, or macOS;
on Linux without systemd a root install stays local, with no service), and
the first host you pair becomes its **anchor**. From then on, every terminal and every write on the
machine waits for your approval, and any other host that pairs waits for your
host to approve it.

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
sudo -H privatae-bastion pair <token>       # token: your host's Network app → Set up a bastion
sudo -H privatae-bastion stepup-enroll      # your second factor, so you can approve here
```

On Windows, from an Administrator PowerShell:

```powershell
& ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Networked
privatae-bastion pair <token>
privatae-bastion stepup-enroll
```

**On your own computer** (run the installer as yourself). The bastion runs
as your user in **local** mode and serves one host. The pairing's
capabilities are the authorization, and approvals work once you enrol a
second factor.

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sh
privatae-bastion pair <token>
privatae-bastion run
```

```powershell
irm https://privatae.ai/bastion/install.ps1 | iex
```

A root install that should stay local passes `--local`
(`… | sudo sh -s -- --local`). Reinstalling over a machine already paired in
local mode keeps it local unless you pass `--networked`. [Local and networked modes](#local-and-networked-modes)
sets out the difference, and [Replacing an agent's SSH keys](#replacing-an-agents-ssh-keys)
how to run a fleet of servers this way.

The installer downloads the binary for your OS and architecture, checks its
SHA-256 against the release manifest, and only then moves it into place; a
failed check installs nothing. That manifest comes from the same place as the
binary. To check its signature too, see [Verify a release](#verify-a-release).

How the service runs on Linux, macOS and Windows, and where the release
binaries and the signed release manifest are served from:
[docs/install.md](docs/install.md).

## Quick start

On your own computer. For a server, see [Install](#install): the installer
run as root sets it up networked, and `run` is the service's job.

```sh
privatae-bastion pair <token>       # token: your host's "Set up a bastion", one use
privatae-bastion stepup-enroll      # your second factor, straight away
privatae-bastion run                # tunnel + lanes up; one daemon serves every host you pair
privatae-bastion status             # or: privatae-bastion ui, the local console
privatae-bastion add-folder ~/projects/notes "Notes"
```

Pairing generates this machine's keys locally and pulls only its certificate
and routing from the host. Until you enrol a second factor, folder grants and
file moves are gated by the signed grant alone (the host verifies its own
factor), and model downloads and root shells are refused outright. After you
do, every one of those waits for your approval here. Each paired host gets its
own loopback control port, starting at `127.0.0.1:7878`. A shared folder's
files stay on this machine: the host keeps only an index, and you confirm the
share on the host with your code.

## Local and networked modes

| | **local** | **networked** |
|---|---|---|
| Where | your own computer | a server, or a machine several people share |
| Installed by | the installer run as yourself | the installer run as root (Windows: `-Networked`), or `sudo -H privatae-bastion set-mode networked` |
| Runs as | your user is fine | the system's service: root under systemd or launchd, LocalSystem on Windows |
| A terminal the host opens | opens on the pairing's capabilities | waits for your approval, for that one session |
| A write (an op, a ship step) | runs on the pairing's capabilities | waits for your approval, bound to that op and its arguments |
| Second pairing | refused | waits for the **anchor** host's approval |
| The anchor | none | the first host paired, or `claim-anchor` |

In networked mode one host is the **anchor**: the one host that approves every
later pairing on this machine. Claiming the anchor requires root, because there
is no authority above the box to ask. On a networked machine with no anchor,
the first `pair` run as root anchors it to that host by itself. A machine
paired first and switched to networked afterwards is anchored with
`claim-anchor` and no token: it is a choice among pairings the box already
holds, and running it again for the same host changes nothing. A token is needed only to name a host this box
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

## Replacing an agent's SSH keys

An agent with an SSH key has a shell on every server the key opens, and the
server's log says only that the key was used. Paired through the bastion, the
agent holds no key that opens anything: each server dials out to its host,
decides what the host may do, and records every decision.

For a fleet of servers:

1. **Install each server as networked** (the installer as root) and pair it
   to your host, which anchors it there. Enrol a second factor on each one.
2. **Make one approval device** that is not the host's machine
   (`device-init` on your own computer, `pin-device <key>` on each server).
   Approvals then come from it, in each server's own words.
3. **Start with reads.** Observe ops (`observe:*`) are read-only and give the
   host the view of each server it needs.
4. **Turn recurring jobs into ops**, not shell sessions. An op is a program
   your host wrote, run in a sandbox first; you approve its terms once, with
   bounds, an expiry and a use count (see [Ops](docs/ops.md#ops-programs-your-host-wrote-run-in-a-sandbox-first)).
   A change across several servers is one [ship plan](docs/ship-plans.md):
   one approval, and each server runs only its own lines.
5. **Keep terminals off** where nobody needs them:
   `sudo -H privatae-bastion switch <host> session off`. That also stops
   root commands. Do not grant `root-exec` on a server you would not hand a
   standing root shell.
6. **Send the audit somewhere the host cannot write.** Every audit row also
   goes to the system log (see [Audit](docs/audit.md));
   point your log collector at it.

When the agent cannot do something without a shell, that is the op to write
next, not the shell to open.

## What the bastion does

Everything is in `client-go/` and compiled into the one binary. Each part has
its own page, listed with one line each in [docs/README.md](docs/README.md):
[tunnel and lanes](docs/lanes.md), [your files](docs/context.md),
[model store](docs/models.md), [approvals](docs/approvals.md),
[ops](docs/ops.md), [ship plans](docs/ship-plans.md),
[service slot](docs/service-slot.md), [observe](docs/observe.md),
[heartbeat and self-update](docs/updates.md),
[memory mirror](docs/memory-mirror.md), [backups](docs/backups.md),
[audit](docs/audit.md), [local console](docs/console.md),
[a Host on this machine](docs/host-on-this-machine.md) and the
[command reference](docs/commands.md).

## Security model

Each point in full: [docs/security-model.md](docs/security-model.md); the link after each goes to its detail.

- **The bastion dials out.** Every lane is a reverse connection to the host;
  no port is opened on an externally reachable interface. ([lanes](docs/lanes.md))
- **Inside the tunnel, only gated listeners**: up to three inference forwards,
  one port per service-slot server and one per coder run, each checked when a
  connection is accepted. ([tunnel](docs/lanes.md#tunnel))
- **A Host on this machine gets the same walls**: mutual TLS against the CA
  pinned at pairing, and the bearer on every lane. ([page](docs/host-on-this-machine.md))
- **Scoped tunnel.** The WireGuard peer's only allowed address is the paired
  host's single tunnel address. ([tunnel](docs/lanes.md#tunnel))
- **No MCP endpoint.** Nothing on this machine drives the host.
- **Grants are verified here.** They arrive signed, the verify key is pinned
  on first use, and a deny always beats an allow. ([DCN stores](docs/context.md#distributed-context-network-dcn-stores))
- **Fixed argv.** Every management op runs a fixed command line; file ops are
  Go handlers with no shell. ([worker lanes](docs/lanes.md#worker-lanes))
- **Approval on the machine, once enrolled.** Folder grants, move plans, model
  pulls and root sessions each need a code from this machine, bound to that
  request, single use. Without a second factor, grants and move plans rest on
  the signed grant alone, and model pulls and root sessions are refused. ([approvals](docs/approvals.md))
- **On an anchored machine, a write needs an approval verified and spent
  here**, bound to the op and its arguments; the writes that take no fresh
  approval are listed. ([approvals](docs/approvals.md#writes-on-an-anchored-machine-wait-for-your-approval))
- **Host-written programs run sandboxed first**, as a dry run with no network,
  and never change anything outside their declared file effects. ([ops](docs/ops.md))
- **A server in the service slot has no network.** The host's tunnel is its
  only way in. ([service slot](docs/service-slot.md))
- **Egress for someone else reaches the public internet, never this
  machine**: a coder run's proxy and an anchored machine's egress lane refuse
  internal addresses and this machine's own (a coder run reaches a LAN host
  you named). A local machine's egress lane refuses this machine and keeps
  your LAN. An address that reaches this machine only through a 1:1 NAT is
  not covered. ([full text](docs/security-model.md))
- **A terminal is checked here and logged.** On a local machine it opens when
  the host asks; on an anchored one each needs an approval for that session;
  a root terminal needs a code entered here. ([session lane](docs/lanes.md#session-lane))
- **Root commands run only under a grant given here with the code**, to the
  anchor host, until the time you chose and at most 30 days; a revoke or
  expiry stops a running command within 2 seconds. ([session lane](docs/lanes.md#session-lane))
- **Root only where there is no one else to ask**: claiming ownership or the
  anchor. ([modes](#local-and-networked-modes))
- **On macOS and Windows, a networked bastion is the system's service**, which
  a signed-in user who does not administer the machine cannot stop. ([install](docs/install.md))
- **Observation changes nothing on the machine.** Observe ops read and report;
  the few that send traffic are named. ([observe](docs/observe.md))
- **A backup's key goes to a host only when you approve it here**, and opens
  that one backup. ([backups](docs/backups.md), [restoring a lost host](docs/backups.md#restoring-a-lost-host))
- **No delete op on shared stores.** The one write lane is a move plan you
  approved, and it archives. ([DCN stores](docs/context.md#distributed-context-network-dcn-stores))
- **Verified releases.** The self-updater checks the manifest's signature and
  the binary's SHA-256 before swapping; the release key never reaches the
  build machine. The installer checks the SHA-256 ([SECURITY.md](SECURITY.md)
  says what that proves). ([self-update](docs/updates.md))
- **No secrets cached for git.** The credential helper fetches a token on
  every auth and stores nothing; which other helpers are kept out depends on
  the git version. ([git lane](docs/lanes.md#git-lane))

To report a security issue, please do not open a public issue. See
[SECURITY.md](SECURITY.md).

## How each claim is tested

Every security claim names the test that fails if it stops being true, and
says where there is none. The full table is one file,
[docs/claims.md](docs/claims.md); `deploy/check-claims.sh` checks that every
test it cites exists in `client-go`.

## How this repo is published

Development happens in a private repository, and its history is not
published. When a release is published, each change merged since the last one
arrives on GitHub as a commit with the same files, titled as the change was
and dated when it was merged; the copy at git.privatae.ai receives the release
as one commit. In both, the release is tagged `v<version>` on a commit whose
tree is identical to the commit the signed release manifest names as
`built_from`. Every binary can be rebuilt from the tag and compared with the
published one: see [Verify a release](#verify-a-release).

Issues and pull requests are welcome on GitHub, at
[github.com/Privatae/bastion](https://github.com/Privatae/bastion). An
accepted change is carried into the development repository and arrives here
with the next release.

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

Cross-compiling the way the release pipeline does, running the tests and
running the fuzz targets: [docs/build.md](docs/build.md).

## Verify a release

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

Each published release in this repository carries the tag `v<version>` (for
example `v0.54.1`). The manifest's `built_from` names the
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
Releases from 0.53.2 on can be checked this way from a clone of this
repository; the tags of earlier releases are not in it.

## Contributing

Issues and pull requests are welcome on GitHub, at
[github.com/Privatae/bastion](https://github.com/Privatae/bastion) (see
[How this repo is published](#how-this-repo-is-published)). Sign-in on the
git.privatae.ai forge is not reachable from the internet, so they cannot be
opened there. Report a security problem by email, not in a public issue (see
[SECURITY.md](SECURITY.md)).

[CONTRIBUTING.md](CONTRIBUTING.md) has the checks a change has to pass
(`go vet ./...` and `go test ./...` in `client-go`, and more) and the
principles it has to respect, the ones the code already follows: the bastion
dials out, fixed argv, no shell in file handlers, approval on the machine, and
capabilities withheld rather than faked when a platform cannot deliver them.

## License

This repository is free software, licensed under the GNU General Public License
version 3 or (at your option) any later version. See [LICENSE](LICENSE).
Copyright Privatae LLC.

You may run it, read it, change it and redistribute it under that license. The
Host the bastion connects to is separate software and is not covered by this
license: a C-Series Host is [Privatae/cseries](https://github.com/Privatae/cseries),
under AGPL-3.0-only, and a Host on Privatae's own platform is proprietary
software. See [SECURITY.md](SECURITY.md#what-you-still-have-to-trust) for what
the bastion holds each to.

The local console vendors [htmx](https://htmx.org) 2.0.10
(`client-go/uiassets/htmx.min.js`), which is distributed under the Zero-Clause
BSD license reproduced in `client-go/uiassets/htmx.LICENSE`. Go module
dependencies are listed in
`client-go/go.mod` and carry their own licenses.
