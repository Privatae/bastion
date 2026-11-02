# privatae-bastion

[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8.svg)](client-go/go.mod)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#supported-platforms)
[![ci](https://github.com/Privatae/bastion/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Privatae/bastion/actions/workflows/ci.yml)

**See every AI agent running on your computer, what each one is doing and what it can reach, and stop any of them. One program, no account, no AI of its own.**

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sh     # macOS, Linux: sudo asks for your password once
privatae-bastion ui                                         # the console, in your browser
```

```powershell
irm https://privatae.ai/bastion/install.ps1 | iex           # Windows: Windows asks for an administrator's yes once
```

It starts watching at once. No Host, no sign-up and no network is needed; a
Host is something you can connect later ([Works with a Host](#works-with-a-host)).

**AI readers and reviewers:** [docs/README.md](docs/README.md) lists every reference page, one line each, and [docs/claims.md](docs/claims.md) is the full table of security claims and the test behind each. [docs/STATUS.md](docs/STATUS.md) says what works today and what does not.

**Contents:** [What it sees](#what-it-sees) · [What you can do](#what-you-can-do) ·
[What it refuses to do](#what-it-refuses-to-do) · [Works with a Host](#works-with-a-host) ·
[Install](#install) · [Your own computer or a shared machine](#your-own-computer-or-a-shared-machine) ·
[Replacing an agent's SSH keys](#replacing-an-agents-ssh-keys) ·
[What the bastion does](#what-the-bastion-does) · [Security model](#security-model) ·
[How each claim is tested](#how-each-claim-is-tested) ·
[How this repo is published](#how-this-repo-is-published) ·
[Supported platforms](#supported-platforms) · [Build from source](#build-from-source) ·
[Verify a release](#verify-a-release) · [Contributing](#contributing) · [License](#license)

## What it sees

- **Every AI agent on the machine**: Claude Code, Codex, Gemini CLI, aider,
  goose, Cline, opencode, Cursor's agent, Open Interpreter, Continue, crush
  and Antigravity by their programs, and any other program holding a
  connection to a model's API ([`agents.go`](client-go/agents.go)).
- **What each one is doing.** For Claude Code: the session's title, its
  folder and git branch, whether permission prompts are off, and the command
  it is running now ([`agentsession.go`](client-go/agentsession.go)). For the
  others: the folder and the tool servers it runs.
- **Who started it**: you at a terminal here, a remote login, a scheduled job,
  a service, or another agent.
- **The scheduled jobs that start agents** (cron and systemd timers, launchd,
  Task Scheduler).
- **The problems in their tool-server (MCP) configs**: a key in plain text,
  a package that is not pinned to a version, a remote server with no
  credential, a server running that no config declares
  ([`mcpconfig.go`](client-go/mcpconfig.go)).
- **What changed since your baseline**: a new agent, a new schedule, a new
  listening port.

The same views are commands, each with `--json`: `agents`, `activity`,
`report`. A report is one Markdown file of all of it, with no prompts in it.

## What you can do

- **Stop an agent**, from the console or `privatae-bastion stop <pid|session>`,
  with your code: a six-digit code from an authenticator app on your phone.
- **Answer what agents ask.** An agent can ask the bastion for something (to
  stop another agent, say); it waits on **Waiting for you** until you answer
  with your code.
- **Mark an agent as yours**, so the ones you did not start stand out.
- **Record a baseline**, and see what is new since.
- **Write a report** of what the bastion knows about this machine.

## What it refuses to do

- **An agent cannot turn it off or widen what it allows.** Installed for the
  whole machine (the default), the bastion runs as the system's service, so a
  program running as you, an AI agent included, cannot stop it. Your code
  lives where only the machine's administrator can read it, so an agent that
  drives your browser can click a button but cannot type the code.
- **It sends nothing about this machine anywhere.** With no Host connected
  its only outside request is for the list of releases
  (`https://privatae.ai/bastion/version.json`, every 6 hours). Session titles
  and prompts never leave the machine, even with a Host
  ([`agentsession.go`](client-go/agentsession.go)).
- **It runs no AI.** Nothing in it calls a model.
- **Its console is this machine's only.** It listens on `127.0.0.1`, and
  opens for the machine's administrator and the account recorded as its
  owner, nobody else ([console](docs/console.md)).
- **Nothing on this machine drives a Host.** There is no MCP endpoint here.

## Works with a Host

A Privatae Host is an AI that works for you. Connected to one, the bastion is
what lets it see your files, use your machine's models and act on the machine
**without handing it your machine**. The bastion dials your Host; your Host
never dials your machine. The only ports it holds open on an outside interface
are its tunnels' WireGuard UDP ports, and WireGuard drops every packet there
that does not come from that Host's key. What the Host may do arrives as a
signed grant that this binary checks here, and anything that would move your
files, download a model or open a root shell waits for your code
([Security model](#security-model), [SECURITY.md](SECURITY.md)).

```sh
sudo -H privatae-bastion pair <token>       # token: your Host's Network app → Set up a bastion
```

A Cloud Host's **Set up a bastion** card gives one line that installs, pairs
and starts the bastion:
`curl -fsSL https://privatae.ai/bastion/install.sh | PRIVATAE_PAIR_CODE='skp_…' sh`, or
on Windows `& ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Pair 'skp_…'`.

The bastion itself needs no Docker, no Python, no database and no separate
WireGuard install. A few features a Host can use need software the machine
must already have: coder runs, the service slot and the memory mirror need a
container runtime (Docker, Podman or nerdctl); folder search runs the bastion
agent, which needs Python 3.8 or later; host-written ops in Python need
`/usr/bin/python3`; and reading an app's accessibility tree on Linux needs
python3 with its AT-SPI bindings. Without them, those features say what is
missing and the rest works.

## Install

**On your own computer**, run the installer as yourself:

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sh
```

It installs the bastion **for the whole machine**: the systemd unit
`privatae-bastion` on Linux, the launchd daemon `ai.privatae.bastion` on macOS,
both running as root. sudo asks for your password once. Your account is
recorded as the machine's owner, so `privatae-bastion ui` opens the console
from it without sudo. Then set up your code, at a terminal:

```sh
sudo -H privatae-bastion stepup-enroll --machine
```

On Windows, `irm https://privatae.ai/bastion/install.ps1 | iex` does the same
with the Windows service `PrivataeBastion`, and Windows asks for an
administrator's yes once.

`--just-me` installs it for your account alone, with no sudo
(`curl -fsSL https://privatae.ai/bastion/install.sh | sh -s -- --just-me`;
on Windows `-JustMe`). Any program running as you can then stop it or change
what it allows, and the installer says so. Where sudo is missing or refuses,
that is what the installer falls back to, and it says that too. An install
for your account alone that is already paired stays where it is when you
reinstall.

**On a server**, run the installer as root:

```sh
curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
sudo -H privatae-bastion pair <token>
sudo -H privatae-bastion stepup-enroll
```

Run as root, it installs the bastion for a **shared machine**: the first Host
you pair is in charge, every terminal and every write on the machine waits for
your approval, and any other Host waits for the one in charge to approve it.
`--personal` or `--shared` chooses either way explicitly.

The installer downloads the binary for your OS and architecture, checks its
SHA-256 against the release manifest, and only then moves it into place; a
failed check installs nothing. That manifest comes from the same place as the
binary. To check its signature too, see [Verify a release](#verify-a-release).

`privatae-bastion uninstall` removes the service and the program and keeps the
state, the audit log included; `--delete-data` deletes that too. How the
service runs on each system, and where the release files are served from:
[docs/install.md](docs/install.md).

## Your own computer or a shared machine

| | **your own computer** (`local` in the code) | **a shared machine** (`networked`) |
|---|---|---|
| Installed by | the installer run as yourself | the installer run as root, or `sudo -H privatae-bastion set-mode networked` |
| Runs as | the system's service (or your account, with `--just-me`) | the system's service: root under systemd or launchd, LocalSystem on Windows |
| A terminal the Host opens | opens on the pairing's capabilities | waits for your approval, for that one session |
| A write (an op, a ship step) | runs on the pairing's capabilities | waits for your approval, bound to that op and its arguments |
| A second Host | asked on this computer's terminal, added only on a yes | waits for the approval of the Host in charge |
| The Host in charge | none | the first Host paired, or `claim-anchor` |

On a shared machine one Host is **in charge** (the code calls it the anchor):
the one Host that approves every later pairing on this machine. Putting a Host
in charge requires root, because there is no authority above the machine to
ask. On a shared machine with none in charge, the first `pair` run as root puts
that Host in charge by itself. A machine paired first and switched to shared
afterwards gets its Host in charge with `claim-anchor` and no token: it is a
choice among pairings the machine already holds. A token is needed only to name
a Host this machine does not serve yet (a fresh machine, or `--rotate`). The
Host in charge can be changed only with its own signed consent, or after 14
days of silence from it.

```sh
sudo -H privatae-bastion claim-anchor [--owner <name>] [--host <host>]   # put a Host already paired here in charge
sudo -H privatae-bastion claim-anchor [--owner <name>] <token>           # a fresh machine, and your Host in charge
sudo -H privatae-bastion claim-anchor --rotate <token>                   # put a different Host in charge
sudo -H privatae-bastion claim-anchor --repin                            # same Host, new address
sudo -H privatae-bastion claim-owner <name>                              # state who owns the machine
```

`claim-owner` is optional. The name shows on this machine's card in every Host
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
  the only ports open on an outside interface are the tunnels' WireGuard
  ports, which drop everything not from the host's key. ([lanes](docs/lanes.md))
- **Inside the tunnel, only gated listeners**: up to three inference forwards,
  one port per service-slot server and one per coder run, each checked when a
  connection is accepted. ([tunnel](docs/lanes.md#tunnel))
- **A Host on this machine gets the same walls**: mutual TLS against the CA
  pinned at pairing, and the bearer on every lane. ([page](docs/host-on-this-machine.md))
- **A Host with no platform reaches your model servers by name, never by
  address**: it names `ollama`, `llm` or `pii`, and the bastion reaches the
  server set on this machine for it, through the forwards' filter, only when
  that address is this machine. ([page](docs/host-on-this-machine.md#the-model-servers-on-this-machine))
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
- **Egress for someone else reaches the public internet, and nothing on this
  machine or your network that you did not name**: a coder run's proxy and an
  anchored machine's egress lane refuse internal addresses and this machine's
  own (a coder run reaches a host you named with `coders set --allow-lan`,
  even when it is this machine or on your LAN). A local machine's egress lane refuses this machine and your
  LAN too; your own machines are reached through their approved lanes. An address that reaches this machine only through a 1:1 NAT is
  not covered. ([full text](docs/security-model.md))
- **A terminal is checked here and logged.** On a local machine it opens when
  the host asks; on an anchored one each needs an approval for that session;
  a root terminal needs a code entered here. ([session lane](docs/lanes.md#session-lane))
- **Root commands run only under a grant given here with the code**, to the
  anchor host, until the time you chose and at most 30 days; a revoke or
  expiry stops a running command within 2 seconds. ([session lane](docs/lanes.md#session-lane))
- **Root only where there is no one else to ask**: claiming ownership or the
  anchor. ([modes](#your-own-computer-or-a-shared-machine))
- **On macOS and Windows, a networked bastion is the system's service**, which
  a signed-in user who does not administer the machine cannot stop. ([install](docs/install.md))
- **Observation changes nothing on the machine.** Observe ops read and report;
  the few that send traffic are named. ([observe](docs/observe.md))
- **A backup's key goes to a host only when you approve it here**, and opens
  that one backup. ([backups](docs/backups.md), [restoring a lost host](docs/backups.md#restoring-a-lost-host))
- **No delete op on shared stores.** The one write lane is a move plan you
  approved, and it archives. ([DCN stores](docs/context.md#distributed-context-network-dcn-stores))
- **A shared folder serves only what its grant leaves in.** Every read and
  move is held to the grant's excludes, `.config/gcloud` and other patterns of
  several folders included, and the search agent's own folder (`.agent`) is
  never read or moved. ([DCN stores](docs/context.md#distributed-context-network-dcn-stores))
- **Verified releases.** The self-updater checks the manifest's signature and
  the binary's SHA-256 before swapping; the release key never reaches the
  build machine. The installer checks the SHA-256, and `install.sh` checks the
  manifest's signature where the machine's openssl can (OpenSSL 3)
  ([SECURITY.md](SECURITY.md) says what each proves). ([self-update](docs/updates.md))
- **No secrets cached for git.** The credential helper fetches a token on
  every auth and stores nothing; which other helpers are kept out depends on
  the git version. ([git lane](docs/lanes.md#git-lane))

To report a security issue, please do not open a public issue. See
[SECURITY.md](SECURITY.md).

## How each claim is tested

Every security claim names the test that fails if it stops being true, and
says where there is none. The full table is one file,
[docs/claims.md](docs/claims.md); `deploy/check-claims.sh` checks that every
test it cites exists in `client-go`. On GitHub, CI also runs every cited test
as root on the runner's own virtual machine, where the sandbox and namespace
tests a container cannot run do run, and fails if any of them skips.

## How this repo is published

Development happens in a private repository, and its history is not
published. When a release is published, each change merged since the last one
arrives on GitHub as a commit with the same files, titled as the change was
and dated when it was merged; the copy at git.privatae.ai receives the release
as one commit. In both, the release is tagged `v<version>` (0.55.0 to 0.55.2
were not) on a commit whose tree is identical to the commit the signed release
manifest names as `built_from`. Every binary can be rebuilt from the tag and compared with the
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

Requires Go 1.26 or newer (`client-go/go.mod`). The binary is pure Go and builds with `cgo` off.

```sh
git clone https://git.privatae.ai/privatae/privatae-bastion.git
cd privatae-bastion/client-go
CGO_ENABLED=0 go build -o privatae-bastion .
./privatae-bastion version
```

Every push to `main` and every pull request into it runs the checks
[CONTRIBUTING.md](CONTRIBUTING.md) asks for in CI: `.github/workflows/ci.yml`
on GitHub, `.gitea/workflows/ci.yml` on git.privatae.ai. On GitHub it also
runs every test [docs/claims.md](docs/claims.md) cites, as root on a machine
of its own, and fails if any of them skips.

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

From 0.53.2 on, each release in this repository carries the tag `v<version>`
(for example `v0.54.1`), apart from 0.55.0, 0.55.1 and 0.55.2, which have no
tag. The manifest's `built_from` names the
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
Only a release tagged here can be checked this way from a clone of this
repository. A release arrives here after it is published, so the newest one
has no tag here until then.

Each release on GitHub carries the six binaries, the signed manifest
`version.json`, its signature `version.json.<first 16 hex of its sha256>.sig`
and `SHA256SUMS`. The release workflow (`.github/workflows/release.yml`)
attaches them only after `deploy/release-assets.sh` has rebuilt the binaries
from the tag and the published signature has verified against the manifest
written from them, so they are the same bytes the installer and the
self-updater fetch. To check a download yourself, compare its sha256 with the
manifest's, and check the manifest's signature against the keys this source
pins (needs Go):

```sh
cd deploy/release-sign
go run . verify bastion <dir>/version.json <dir>/version.json.<…>.sig $(go run . pinned ../../client-go/release_sign.go)
```

`deploy/release-assets.sh v<version> <dir>` does all of it from a clone,
rebuild included, for any release tagged here.

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
