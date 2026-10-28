# Changelog

All notable changes to the bastion.

The version in `deploy/VERSION` on `main` is the next release, not necessarily
the one machines run. A merged change waits there until it is published. The
published version is whatever <https://privatae.ai/bastion/version.json> names
at the moment, and it is the only version a bastion will update to. Between a
merge and a publish, `main` is ahead of the manifest.

Two things can keep a version listed here from reaching most machines:

- **Superseded before publishing.** When a second release is merged before the
  first is published, only the later one is published, and it carries the
  changes of both.
- **Held.** Automatic updates move our own machines to a published version
  first, and everyone else only after it has run on them for a day without a
  machine going silent. A version that fails that check is held: automatic
  updates move no other machine to it, and it is never released again, only
  superseded by a newer version.

From 0.39.1 on, a heading marks a version *not published* or *held* once
that is settled. The newest entries may not be published yet; the manifest
says which version is. Older entries are not marked.

## 0.57.0

- **Pairing with a Cloud Host is one pasted line.** A Host's "Set up a
  bastion" card now gives a pairing code, `skp_…`, that carries the token,
  the Host's enroll address and the SHA-256 of the Host's CA. `pair <code>`
  (or the code on standard input after `pair -`) takes the CA from the enroll
  port's own TLS chain, keeps it only under that fingerprint and only when the
  port's certificate verifies under it for `host.cseries.internal`, then pairs
  exactly as `--redeem-url` with `--host-ca` does. There is no certificate
  file to save, so the step people skipped ("open host-ca.pem: The system
  cannot find the file specified") is gone. `--host-ca` still works as before.
- **The installers pair and start in one go.** `install.sh` with
  `PRIVATAE_PAIR_CODE='<code>'` in its environment (the card's line is
  `curl -fsSL https://privatae.ai/bastion/install.sh | PRIVATAE_PAIR_CODE='skp_…' sh`)
  and `install.ps1 -Pair '<code>'` install or update the bastion as before,
  hand the code to `pair -` on standard input, then start the bastion, or restart it when it
  was running, and end with one plain sentence and `status`. On Windows that
  is the logon task (every running copy is stopped first, so the new one gets
  its control port), or the service on a networked machine; on a machine whose
  bastion is already the Windows service, `-Pair` pairs that service from an
  Administrator PowerShell instead of installing a second bastion. On Linux as
  yourself it is a systemd user unit, with lingering asked for and the outcome
  said; on macOS a LaunchAgent; as root, the system service. Without the code
  both installers behave as they did.
- **The code is in no process's arguments.** On macOS and Linux it comes
  only from the environment: an argument would sit in the installer shell's
  command line for the whole install, where any user of the machine can read
  it with `ps`, and one at the same address could redeem it first. A
  process's environment is readable only by its owner and root. `install.sh`
  reads the variable before it starts any program and unsets it, so nothing
  it starts inherits it. An empty or partial code is refused before the
  download. `install.sh` now names no argument it refuses, so a code given in
  the wrong place is never printed back. On Windows the code stays a
  parameter of the script, inside the person's own PowerShell.
- **On Linux, as yourself, the copy that serves is the one the installer
  started.** Before the user unit starts, every copy of your bastion running
  outside it (left in a terminal, or from another path) is stopped, as
  install.ps1 does on Windows. Otherwise the unit's copy only waits behind the
  old one's run lock, and the old copy never reads the new pairing. The
  installer then checks for a few seconds that the unit is running and keeps
  the same process. A unit that keeps restarting is reported as not running,
  with its log command, and the install fails.
- **A local bastion can serve a second Host, when you say so at the machine.**
  A local bastion used to serve one Host and refuse any other, so a person
  with two Hosts of their own (a Cloud machine beside a platform Host) could
  not pair the second at all. `pair` now asks on this machine's terminal,
  `/dev/tty` or the Windows console, never standard input, so a code piped
  in by an installer still needs a person to answer: "This computer already
  serves your Host … Add … as well? [y/N]". Only y or yes adds it; the first
  pairing is untouched; with no terminal it is refused. Other callers
  (`claim-anchor`, the pairing op) keep the refusal. On a local machine that
  serves two Hosts, each changes only the servers it built and stops only the
  coder runs it started. The name in the question is the token's, so anything
  in it but a plain host name is shown quoted and escaped.
- **`pair` exits 3 when the Host is already paired here.** Nothing changes, and
  the installers report it as already connected. Over TCP, with a pairing
  code or `--host-ca`, a Host of the same name under another CA (Cloud names
  repeat) is a plain refusal, not exit 3, before the redeem and after it. A
  pairing code that names a field twice is refused.
- **An enroll port that does not answer says why within 10 seconds.** A Cloud
  Host opens its pairing port only to the address the browser used when the
  card was opened, for 15 minutes; from anywhere else the port does not
  answer, and `pair` used to wait for the system's connect timeout. It now
  stops after 10 seconds with that reason and what to do.
- **The local-mode refusal names this system's way to a networked bastion**
  (`install.ps1 -Networked` from an Administrator PowerShell on Windows,
  `install.sh --networked` as root elsewhere) and says that the Host already
  paired would have to be paired again with it. It used to name the Linux
  script on Windows.

## 0.56.0

- **New: a Host with no platform can use the model servers on this
  computer.** A Host running on this computer, or in a virtual machine on it,
  can reach the model servers here (Ollama, a local language model server, a
  personal-data filter) by name through the bastion, and is told which of
  them it can use. It starts working once your Host supports it.
- **Changed: for a Host with no platform, model management reaches only this
  computer.** Listing, downloading and removing models for such a Host now
  reach the model server set here only when that server is on this computer.
  One set to another computer is refused, and the bastion's log says which
  setting is not used and what to set. Such a Host is also told only of
  the model servers it can use, and no longer of the service slots, or of
  coder runs when it is in a virtual machine, since neither runs for it.
- **Changed: on a local machine, the internet lane reaches only public
  addresses.** A Host can no longer use a local machine's internet lane (the
  egress lane) to reach devices on your home or office network at their
  private addresses, such as 192.168.x.x or 10.x.x.x, or the private ranges
  many VPNs use, as was already the case on an anchored machine. Your own
  machines are reached through their approved lanes. A device that has a
  public address, as many do over IPv6, is still reached at that address.
- **Changed: plain-HTTP requests through the bastion are checked one per
  connection.** On the internet lane and a coder run's web proxy, a
  plain-HTTP (not HTTPS) connection now carries one request, which is checked
  before it is sent on; anything sent after it closes the connection. Before,
  later requests on the same connection reached the destination unchecked. A
  malformed or ambiguous request is refused, and every refusal now says why.
- **Safer: file access in a folder you shared stays inside it.** When a Host
  lists, reads or moves files in a folder you shared with it, the bastion
  stays inside that folder. If the folder, or any folder on its path, is later
  swapped for a link to somewhere else, the bastion refuses until the folder
  is shared again, and a file or folder inside it swapped for a link is never
  followed out of it. Search, which goes through the folder's own search
  agent, is not part of this change.
- **Safer: the bastion limits how much it holds of what a Host sends.** On
  the internet lane, the terminal and root commands, coder runs, the memory
  mirror (the copy of your Host's database kept here) and the bastion's
  check-in with its Host, a message from the Host is read only up to a set
  size and refused past it, or passed along or dropped as it arrives. A Host
  can no longer make the bastion hold a message of any size in memory. A
  coder run's web proxy now carries at most 1024 connections at once, and the
  memory mirror at most 8.
- **Safer: asking to share a folder with a Host has limits.** Any user on the
  computer can send that ask to the bastion, so each ask is now read only up
  to a set size, and the number of asks open at once is capped, per user and
  in total; past the cap, the ask is told the bastion is busy and to try
  again.
- **For contributors: the fuzz check in CI no longer fails on a timing bug in
  Go's own fuzzer.** A real failure still fails it. The program itself is
  unchanged by this.

## 0.55.3

- **A pairing change reaches every Host on the machine at once.** Each pairing
  beats its Host every 60 seconds, and the beat is how every Host on the
  machine learns that a pairing went active or was revoked. Approving or
  revoking a pairing changed it on disk immediately but triggered no beat, so
  every Host kept the old state for up to a minute: a connection request to a
  Host the anchor had just approved was refused as not on a shared machine. Now
  a grant that makes a pairing active, and a revoke, make every running
  pairing beat right away. A refused grant, or a re-sync of a pairing that is
  already active, beats nothing.

## 0.55.2

- **A search reply says how its text was sanitized.** Every successful reply
  from the bastion agent (search, read range, catalog) was stamped
  `sanitized: true`, while the agent the bastion deploys runs in `flag` mode,
  which replaces e-mail addresses, phone numbers, card, bank and ID numbers,
  IP and MAC addresses and keys, and leaves names, street addresses and
  dates of birth in. A reply now carries `sanitize_mode` (the mode this
  bastion wrote into the agent's manifest, or for an agent run by hand the
  mode it reports, else `unknown`), `sanitized` true only for `sterilize`,
  and `sanitize_note` saying what the mode leaves in. A reply cannot raise
  the mode this bastion wrote.
- **The README says what the bastion needs.** It said "no Docker, no Python".
  The bastion itself needs neither, and the README now names the optional
  features that do: coder runs, the service slot and the memory mirror need a
  container runtime, folder search needs Python 3.8 or later, Python ops need
  `/usr/bin/python3`, and the Linux accessibility reader needs python3 with
  AT-SPI. It also said Go 1.25; `client-go/go.mod` needs 1.26.
- **GitHub releases carry their files.** A new workflow,
  `.github/workflows/release.yml`, runs on each release tag (and by hand for
  an earlier one): `deploy/release-assets.sh` rebuilds the release from its
  tag, writes the release manifest from the rebuilt binaries with
  `deploy/manifest.py` (which `publish.sh` now uses too, so the two cannot
  differ), and fetches the signature published for that manifest. Only when
  the signature verifies are the six binaries, `version.json`, its signature
  and `SHA256SUMS` attached to the release. Releases 0.53.2, 0.54.0 and
  0.54.1 were rebuilt this way and each matched its signed manifest.
- **The lab harness is out of the release build.** `mode=lab` drove one test
  lab's own cluster and database, and its layout was in the published source.
  It is now built only with `-tags lab` and is not in the published source; a
  release bastion answers a lab run with exit 126, as a bastion without a lab
  always did.
- **staticcheck is clean** on linux, darwin and windows, for both Go modules,
  and CI runs it (`deploy/staticcheck.sh`, a pinned staticcheck release, with
  the per-OS runs merged so code used on one OS only is not reported unused).
  Unused code is removed and error strings no longer end in punctuation; no
  behaviour changes.
- **The claim tests a container cannot run now run on GitHub.** 25 tests the
  claims table cites (the op and action-op sandboxes, the egress tests in
  private namespaces, the root command watch) skipped in CI, because a CI
  container has no systemd, no namespaces of its own and no nftables. A new
  job runs every cited test as root on GitHub's discarded virtual machine and
  fails if any skips; `deploy/check-claims.sh --skipped` names them.

## 0.55.1

- **A root op's tasks are capped.** An op's tasks were capped at 64 with
  `RLIMIT_NPROC`, which the kernel never applies to root, so a root op could
  start as many tasks as it liked until its time limit. A root op now runs
  in a systemd scope of its own in `privatae_ops.slice` with `TasksMax=96`,
  which counts every task in it, root's included: the op's 64 and the
  bastion's two processes that start it. Those two run with one CPU's worth
  of Go runtime threads (`GOMAXPROCS=1`), so they take the same share of the
  cap on a machine of any size: with the runtime set for 64 CPUs they took
  44 of the 96, and set for 256 no root op could start. The scope's process
  reads its own cgroup's `pids.max` before the op starts, and the op's
  report carries `tasks_capped` only when that is the cap. Where no scope
  can be made (no systemd, no pids controller, or `systemd-run` failing),
  the op runs as before and its report's `tasks_note` says its tasks were
  not capped, and why. A user op's tasks are held by `RLIMIT_NPROC` as
  before, and its report says so. A scope is killed with the run at the
  time limit, when the bastion stops, and by the startup sweep. Two ops can
  run at once, so an action op's memory watch now reads each other op's
  unit or scope in the slice as another program: it yields when a root op
  beside it makes the machine wait on memory, as it did when root ops ran
  in the bastion's own cgroup, and its own unit still never counts.

## 0.55.0

- **A local machine's egress lane never reaches the machine itself.** Before,
  on a machine with no anchor the lane vetted no destination, so a host could
  dial this machine's own services through it: `POST
  http://127.0.0.1:11434/api/pull` reached ollama whatever the `models` switch
  said. It now refuses `localhost` names, loopback and unspecified addresses
  (`0.0.0.0/8` and `::` included), link-local addresses (the cloud metadata
  address included), the rest of `64:ff9b::/32`, the deprecated IPv6 forms
  below, and any address this machine takes as its own, as the anchored lane
  checks them, also inside an IPv4-mapped, NAT64 or 6to4 address. The LAN
  stays reachable: a private, CGNAT or reserved address that is not this
  machine's is dialled. Every address a name resolves to is checked, and only
  those addresses are dialled, never the name again.
- **A container or VM on this machine is this machine, not the LAN.** On
  Linux, an address the kernel routes straight onto a container's veth, or
  onto a bridge whose every port is a veth, a tap or a dummy (the bridge
  networks Docker, Podman, LXD and libvirt make for their containers and
  VMs), is refused as this machine. A route through a gateway on such a link
  leaves, and a link an IPv4 or IPv6 default route of the main table goes
  out of (any nexthop's, for a multipath default) is never inside: a bastion
  that is itself in a container reaches the internet through the machine it
  runs on, and dials the network on its own veth, its LAN included, as
  before. Before, the local egress lane dialled such an address as LAN,
  so a host could reach a service in a container here, `172.17.0.2:11434`
  for one, though the same service on loopback was refused. A bridge with a
  network card, a bond or a VLAN among its ports is still the LAN. Every lane
  reads the same check, so a coder run's proxy, the anchored lane and the
  backup lanes now also refuse a public address on such a network; their
  private addresses were refused already. macOS and Windows have no route
  lookup here, so there such an address is still dialled.
- **Every lane refuses the deprecated IPv6 forms.** IPv4-compatible `::/96`,
  IPv4-translated `::ffff:0:0/96` and site-local `fec0::/10` are no
  destination of their own, and where each is delivered depends on the
  platform. A coder run's proxy and the backup lanes already refused them; the
  egress lane now does too, anchored or local, by address and in any answer a
  name resolves to. The anchored lane refuses nothing else it did not refuse
  before. All the lanes now read one address classifier.
- **Both egress lanes try each vetted address, as Happy Eyeballs does.** A
  name with more than one address is dialled at each in order, the next
  starting as soon as an attempt fails or when none has answered within
  300 ms, and the first to answer is used; the others are cancelled, and one
  that connects anyway is closed. Before, the anchored lane dialled only the
  first address, and a coder run's proxy gave each address an even share of
  the dial budget, so an address whose packets go nowhere held up the next
  one for seconds. The next one now starts within 300 ms, about what the OS
  dialler took when it was given the name.
- **`pair` says to enrol a second factor after every pairing that has none.**
  It said so only after it anchored a networked machine, so a local pairing,
  one over TCP or a unix socket, and a later host on an anchored machine were
  told nothing, and on a local machine a folder grant then installs on the
  host's signed grant alone. The line names `--host` when more than one host
  is paired, and `sudo -H` only when `pair` itself ran with machine authority,
  so a local install is told to enrol as its own user. A pairing that keeps
  its factor (a `--replace`), or a machine with an approval device pinned, is
  not told.
- **A root-command grant lasts at most 30 days.** It was a year. `root-exec
  grant --for 31d` is refused and says the longest term; grant again before
  it ends. A grant given under the longer term ends 30 days after it was
  given, and `root-exec` shows that end. A grant file with no grant time is
  refused, since it cannot be held to the term.
- **SECURITY.md, the README's license section and `docs/host-on-this-machine.md`
  name each kind of Host.** They described only a Host on Privatae's platform.
  They now say that a C-Series Host runs on your own machine in its own Linux
  virtual machine, is open source (Privatae/cseries, AGPL-3.0-only), needs no
  Privatae account, and that `npx cseries` sets the bastion up networked,
  paired, anchored and with a second factor on every pairing (the commands are
  shown); that C-Series Cloud and a network membership are optional and paid;
  and that a Host on Privatae's own platform is the case where the Host's
  software is not open source.
- **Security reports go to security@privatae.ai,** the address
  privatae.ai/.well-known/security.txt names. SECURITY.md said info@.
- **`docs/models.md` says what stops a host changing your models on a local
  machine.** It told you to scope the pairing on your host, which a local
  machine never reads. There, switching `models` off for the host is what
  filters the ollama forward, and the egress lane is no way around it. On an
  anchored machine the forward filters for every pairing, which the page now
  says too.
- **A tunnel endpoint the host sends must be one host and port.** The
  pairing response's `endpoint` and `endpoints`, and the endpoints in a
  heartbeat's rotate directive, were written into the WireGuard
  configuration unchecked. That configuration is one setting per line, so an
  endpoint with a newline in it added settings of its own:
  `203.0.113.7:51820` followed by a newline and `allowed_ip=::/0` let the
  tunnel carry every IPv6 address, not only the host's. An endpoint must now
  be an IP address or a host name with a port from 1 to 65535, and nothing
  else, no space or control character. A pairing response with any other is
  refused and nothing is saved, and a rotate directive with one is not acted
  on. A WireGuard key must be 32 bytes. The tunnel's peer is now configured in
  one place, which checks every value it writes.
- **A pairing file that holds such an endpoint is listed but never served.**
  An older build may have saved one. Its tunnel and lanes never come up, and
  `run` names the file and says why. Every other pairing still loads and
  serves, `status` shows the pairing as `invalid` with the same reason, and
  `unpair` removes it, as does pairing that host again with `pair --replace`.
  One such file no longer stops `run`, `status` and `unpair` for the whole
  machine.
- **Such a pairing cannot hold the anchor or be approved, and no host is told
  of it.** `claim-anchor` marked it active and anchored the machine to it; it
  now refuses, says why, and changes nothing. An approval from the anchor
  host marked it active and started it with the endpoint its file holds; it
  is now refused. The heartbeat and the anchor host's pairing list leave it
  out: a host knows only the states active, pending and revoked, and could
  show a pairing in any other state as active.
- **A harness run's agent credential is readable only by the harness.** The
  credential file was readable by every user on the machine (0644), in a
  folder anyone could open and write (0777), for the length of the run. A
  bastion running as root now hands the folder (0700) and the file (0600) to
  the user the harness image runs its agent as (uid 10005). One that is not
  root cannot hand them over, so it leaves them open for the agent, and the
  folder sits inside one that only the bastion's own user can enter.
- **A harness run's tree is out of other users' reach.** In a worktree run the
  tree mounted at `/work` was opened to every user (0777), its top folder
  included, in the shared temporary folder. Any local user could read or
  change the Host's tree during the run. It now sits in a folder only the
  bastion's own user can enter, as a git run's tree already did, and a run
  refuses a tree whose folder other users can enter. Opening the tree for the
  agent no longer follows a link in it. Before, on a bastion running as root,
  a link in the repository, to `/etc/shadow` for example, made the linked
  file world-writable. A file is opened as 0666, or 0777 if it was
  executable, so a git run no longer commits every file as executable.
- **A worktree run returns only what is in its tree.** A file swapped for a
  link while the tree was being packed, or a folder swapped for a link, was
  read through the link, so a bastion running as root could return any file
  on the machine to the Host. Each name is now opened inside the folder
  already open above it, never through a link, and goes in only if it is the
  plain file or folder that was looked at. On Linux a device or pipe swapped
  in for a file in that gap is not opened either: opening some devices does
  something by itself. Links, pipes, devices and sockets are left out
  (before, each came back as an empty entry of its kind), and the run's
  result names them in `worktree_skipped`, with `worktree_skipped_count`.
- **A coding agent can no longer run code as the bastion through the
  repository's git settings.** In a git run the bastion committed and pushed
  in the agent's own folder, `.git` included, so a hook, a file system
  monitor, a filter, a signing program or a changed remote the agent set ran
  as the bastion's own user, which can be root, or sent the push, with its
  token, to another server. The bastion now makes its own fresh clone, in a
  folder the agent cannot reach, copies in the agent's plain files and
  folders (never a link, never anything of its `.git`), and commits and
  pushes only there. The branch gets one commit with the agent's final
  files; the agent's own commits are not pushed one by one. A link the
  agent made is left out and named in `worktree_skipped`; a link the
  repository already holds stays as it is. Every git the bastion runs for a
  harness or a mirror runs with no hooks, no file system monitor, no `ext::`
  transport, and no system or user git settings of the machine.
- **The agent in a git run no longer holds the push token, and no process
  argument shows it.** The agent's clone named the repository with the
  run's token in it, so the agent could push straight to the repository
  during the run, past the bastion's copy, and every git the bastion ran
  for the run had the token in its arguments, which any local user can
  read. Every git call now names the repository without the token and gets
  it from its environment, as an `Authorization` header sent to that
  repository's address only; no clone's config holds it, and a run is
  refused if the token is in any file of the agent's clone's `.git`.
- **A user-privilege op is no longer refused because other programs run as
  its user.** An op's tasks are capped at 64, and the cap counted every task
  the machine ran as the op's user (`privatae-session`, or `nobody`, which
  system daemons share), so on a busy machine a user op could not start or
  could not fork at all. The op now runs in a user namespace of its own,
  as the same user and seeing every file's real owner, where the cap counts
  only its own tasks. Where the machine has no user namespaces, the op runs
  as before.
- **A harness run's git calls carry the harness identity.** git made one
  from this machine's user and host name instead, which cost a host name
  lookup per call (seconds where there is no resolver) and wrote this
  machine's name into the clone handed to the agent.
- **A run whose agent container cannot be removed uses nothing of its
  tree.** A failed removal was ignored, so an agent still running could go
  on writing the tree while the bastion read it. The run now fails, says
  so, and copies, returns and pushes nothing.
- **A git run whose commit fails pushes nothing and fails.** A failed add or
  commit was ignored and the branch pushed anyway, and the run read as
  successful. It now ends the run with an error and no push. A run in which
  the agent changed no file pushes no branch and reports `changed: false`.
- **Repositories that keep files in Git LFS work in git runs again.** No
  user git settings are read any more, so the LFS filter `git lfs install`
  sets there was lost. When `git-lfs` is installed, the bastion now supplies
  the standard LFS filter itself on its own git commands, sends the large
  files before the push, and sends them only to the repository's own LFS
  address, whatever a `.lfsconfig` the agent wrote names. A filter of any
  other name in a `.gitattributes` still runs nothing. Tested with git-lfs
  3.7.1.
- **Names that open as `.git` on Windows or macOS are left out of a git
  run's copy.** Besides `.git` in any letter case, the copy now leaves out
  `.git` followed by dots or spaces or a `:`, the short name `GIT~1`, and
  `.git` with the characters HFS+ ignores, the names git itself refuses, so
  no file the agent made can be written into the clean clone's own `.git`.
- **A run's tree has a size limit, and a file is never read into memory
  whole.** A file of any size in the tree, even one that takes no disk
  space, was read whole into memory, so an agent could make the bastion run
  out of memory. A worktree run now returns at most 9 MiB of tree, which is
  what fits in one message to the Host beside the transcript; a larger tree
  is refused with `worktree_too_large` and none of it is returned. A git run
  copies at most 2 GiB, and refuses a larger tree with `tree_too_large`
  before it pushes anything; each file and folder counts 512 bytes and its
  name besides its content, so a tree of millions of empty files is refused
  too, and the copy keeps nothing per file in memory. Of the entries left
  out, the count is kept in full and the first 100 names. A folder is read
  512 names at a time, each counted as it is read, so a folder of millions
  of names is refused without being read whole first. A result too large for one message to the Host
  is refused with `result_too_large` instead of being lost on the way.
- **The local console shows a pairing that is not served as "invalid".** A
  pairing whose file holds an endpoint this build refuses showed as active
  on the console when its stored state was empty, as it is in older files.
  It now reads as the setup page and `status` read it.
- **Built with Go 1.26.10, golang.org/x/net 0.61.0, x/crypto 0.58.0 and x/sys
  0.49.0.** `govulncheck` finds 13 known vulnerabilities this code reaches in
  Go 1.25.14 and x/net 0.57.0, which 0.54.1 was built with: in crypto/x509
  (intermediate certificates since found compromised were still trusted),
  crypto/tls, net/http and HTTP/2, net/textproto, os and html/template. With
  these versions it finds none. The
  build image is still pinned by digest, and CI runs in the same one. The
  module now needs Go 1.26, as x/net's fixed release does. A published release
  is still rebuilt by `deploy/verify-release.sh` with the toolchain its own
  tag pins.
- **`go test ./...` passes for a contributor who is not root.** A root
  command now starts in `/` when the process cannot enter root's home, as it
  already did when that home is missing; the bastion runs these commands only
  as root, so on a machine nothing changes, and the root-command tests now run
  as any user. `TestTreeCheckoutMovesOnlyForward`, which needs a tree root
  owns, skips as another user, and `TestClaimAnchorWithNoToken` checks the
  refusal without machine authority and then skips the rest, where it passed
  having checked nothing more.
- **The tests name no folder of our own build machine.** The sandbox tests'
  fixture folder is `/srv/privatae-optest` (`/tmp` cannot hold an op's
  effects), and the action tests' run note asks for any folder outside
  `/tmp`.
- **How this repository is published (docs only).** From this release on,
  GitHub receives each change merged since the last release as its own commit,
  titled as the change was, instead of one commit per release. The README,
  CONTRIBUTING.md and SECURITY.md say so, and say that releases from 0.53.2 on
  can be verified from a clone, since the earlier tags are not public.
- **The personal-data check reads what it used to miss.** A listed term
  written right after a backslash escape (`\n`, `\t`, `\u00e9`) is found, and
  so is any value inside a run of base64 or base64url that decodes to text.
  The reserved entity ids are read from `/etc/privatae/reserved-entity-ids`
  (one per line, `RESERVED_ENTITY_IDS_FILE` to point elsewhere) instead of
  being written in the script; where that file is absent, as in public CI,
  the entity-id check is skipped and the run prints a NOTE, as the term check
  already does without its key. A file that holds no id, or a line that is
  not one, fails the run.
- **The former-name check reads comments and Markdown.** A kept identifier
  is set aside only in Go code; in a comment, this changelog or any other
  file it is a hit like the bare word, and the two entries that spelled the
  device-fingerprint prefix out now name `fpSANPrefix` instead.
- **CI on GitHub.** `.github/workflows/ci.yml` runs the jobs of
  `.gitea/workflows/ci.yml` on GitHub Actions in the same Go image, pinned by
  the same digest, with no action from the marketplace and a token that can
  only read. A step fails if its digest stops matching `deploy/build.sh`.
- Tests use documentation addresses (`2001:db8::/32`, `203.0.113.0/24`) and
  neutral paths, and comments state their reason instead of citing a pull
  request by number; a test keeps published source free of such numbers.

## 0.54.1

- **No change to what the bastion does.** The README is now a short front
  page: install, quick start, local and networked modes, a summary of the
  security model, how this repository is published, and how to build and
  verify a release. The reference text moved into one page per topic under
  `docs/`, listed in `docs/README.md`, with only its headings and links
  changed. The README and CONTRIBUTING.md now say that issues and pull
  requests are welcome on GitHub.
- **The claims table is its own file, `docs/claims.md`,** and
  `deploy/check-claims.sh` reads it there. Two rows that cited two tests each
  now cite one test per row, so the check passes again.

## 0.54.0

- **Every audit row also goes to the system log.** The rows written to
  `mgmt_audit.jsonl`, `pairing_audit.jsonl` and each pairing's `audit.jsonl`
  (terminals, root commands, store ops, op runs) are also written to the
  machine's system log, so a log collector can keep them where no host can
  write: syslog facility `auth`, tag `privatae-bastion-audit` (the journal on
  systemd) on Linux and macOS, and the Application event log, source
  `PrivataeBastionAudit`, on Windows, registered when the system service is
  installed and removed with it. Each line is the file's row with `audit`
  (the file) and `pairing` added, and a root command's text left out (its
  digest and length stay). The lines go through a bounded queue, so a slow or
  stuck system log never holds up the audited op; a full queue drops lines and
  the next line carries `system_log_dropped`. The file stays the record.
- **A server is networked and anchored by default.** `install.sh` run as root
  now installs the networked bastion (systemd on Linux, launchd on macOS);
  `--local` keeps a root install local, a reinstall over a machine already
  paired in local mode keeps it local unless `--networked` is passed, and run
  as your own user it is local as before. On a networked machine with no anchor, the first `pair` run with
  machine authority anchors it to that host. Before, such a machine refused
  every op until `claim-anchor` was run by hand; now it is anchored at once:
  every terminal and every write waits for the person's approval, and any
  later host for the anchor's. `pair` then says to
  enrol the second factor. `claim-anchor` with no token on a machine already
  anchored to that host now succeeds and changes nothing (an installer that
  anchors after pairing finds the work done); naming another host is still
  refused without `--rotate`. The Windows installer is unchanged: `-Networked`
  as before.

## 0.53.2

- **No change to what the bastion does.** Two code comments named source files
  of the Host program; they now describe them instead, so the release's source
  can be published to the member repository as built. CI checks for such
  names before a change merges.

## 0.53.1

- **`switch` turns a capability family off for a host from a terminal.**
  `sudo -H privatae-bastion switch <host> <family> on|off` writes the same
  local deny list the console page's switch does, so it can only remove
  reach: off makes this machine refuse that family for that host and tell it
  why, and on clears the refusal without granting anything past the host's
  signed grant. Both directions need machine authority. `switch --list`
  prints every paired host's families, on or off, one per line, for a person
  or a setup script on a machine with no browser; beside a system service on
  macOS or Windows it is refused to an ordinary account, whose own state is
  not the machine's. The deny list is now replaced whole (temp file and
  rename) under a lock both writers take, so the gate never reads it half
  written and a switch from the page and one from a terminal cannot drop
  each other.
- **`release-sign` signs C-Series Cloud manifests.** It accepts the kind
  `cseries-cloud` beside `bastion` and `bastion-agent`, with the same
  statement and keys, for the manifest a C-Series Cloud machine's updater
  checks before it moves to new images or a new overlay.
- **`release-sign` signs the C-Series App Store catalog.** It accepts the kind
  `cseries-store`, with the same statement and keys, for the catalog a
  C-Series Host checks before it lists or installs an app from the public
  store. A signature for one kind does not verify as another.
- **Fixed: `stepup-enroll --console-only` refused root on Linux.** The
  startup check recorded whether the process administers the machine only
  when a macOS or Windows system service was installed, and on Linux the
  service is the systemd unit, so that check never ran there and root was
  told it does not administer the machine. Root on Linux enrols into its own
  state, which is the state the unit reads. An ordinary account on Linux is
  still refused, and so is every account on macOS and Windows until the
  system service is installed. `approvals-owner` shares the rule and now takes
  root on Linux the same way.
- **`pair` takes the token on standard input.** `pair -` reads it as the first
  line of standard input, so the token is not in the process list while
  `pair` runs or in the shell's history after. Every form of `pair` takes `-`
  in place of `<token>`, and the token as an argument works as before. `pair`
  with no token is still the usage error, whatever standard input is: some
  terminals do not register as one, and reading there would wait with nothing
  said. At a terminal, `pair -` asks for the token on standard error. A first
  line that is empty, more than one word or longer than 4096 bytes is refused,
  and no refusal repeats what was read.

## 0.53.0

- **A Host with no platform in a VM on this machine can pair over TCP.**
  `pair --redeem-url https://127.0.0.1:8810/v1/local/redeem --host-ca <pem file> <token>`
  redeems the token on the Host's enroll port (`POST /v1/local/redeem`, the
  platform redeem's body) over TLS that trusts that CA and nothing else, no
  system roots, and checks the name `host.cseries.internal` on the Host's
  certificate. The URL must be `https://<host>[:<port>]/<path>`, with no user
  info, query or fragment. `--host-ca` is required with it and refused with a
  unix or platform pairing, and must hold CA certificates only; all of this is
  checked before the token is read, so a refusal dials nothing. The redeem
  follows no redirect: an enroll port that answers with one is refused as it
  answered. The Host's answer must say transport `tcp`, carry the same CA as
  `--host-ca` and an operator certificate for this bastion's key that the CA
  signed for client use, and name a lane on the host the redeem URL names.
  The pairing records transport `tcp`, the lane address and the CA, which is
  pinned as for a unix pairing: a `pair --replace` under another CA is
  refused before the redeem dials, and a pairing does not change transport
  on a `--replace`.
- **Its lanes go to the Host's lane port**, the address its answer names,
  with the same mutual TLS as the unix lane socket: this bastion's operator
  certificate, which the Host knows it by, the pinned CA as the only root, and
  the name `host.cseries.internal`. Then the same bearer and protocol: egress,
  management, the two parked harness workers, sessions, git, the heartbeat
  and what its reply directs. `status` and `pair` show the lane address.
- **What a TCP pairing does not have yet.** No WireGuard forwards: no ollama,
  LLM or PII forward, no service slots, no endpoint rotation, as for a unix
  pairing. No coder runs, on any machine, Linux included: a run's control
  plane is a tunnel port or a socket in a unix pairing's runs directory, and a
  TCP pairing has neither, so run-up for a TCP-paired Host is refused before
  any container starts, and so is every run-up while this machine's pairings
  cannot be read. Off Linux, coder runs stay refused for every pairing,
  as before; running them inside the Host's VM is not built.
- `unix://` redeem URLs work as before.
- **Beside a Windows system service, the signed-in person approves in their
  own tray.** The service serves a named pipe, `\\.\pipe\privatae-bastion-approvals`.
  Its ACL admits SYSTEM, Administrators and interactive users. Interactive
  users get read and write and no right to create an instance of the pipe.
  Remote clients are refused. The service identifies each client from the
  pipe (`GetNamedPipeClientProcessId` and that process's token) and serves
  only a process that runs as the person signed in to its own session, in an
  active session, and of those only the account that owns this machine's
  approvals (below); every other account is refused for list, deny and
  approve alike. Through it a client can list the pending step-up requests,
  in the words `approvals` prints. It can approve one request id with a code
  from the authenticator enrolled here, checked by the existing step-up check
  and bound to the sha256 of the purpose the client was shown. It can deny
  one, which needs no code.
- **`privatae-bastion approvals-owner --sid <SID> [--replace]`**, with
  machine authority, records that account in the service's state
  (`approvals_owner.json`); an installer's elevated step passes the SID of the
  account that ran it. The same SID again changes nothing. A different SID is
  refused and the recorded owner stays, unless `--replace` is given, which is
  taken only on a console (an Administrator terminal), never with output
  captured as an installer runs it. A record that cannot be read is treated
  the same way. With no readable owner, the pipe serves nobody.
- **The pipe's name is never free while the service serves it.** A
  replacement instance is created before a failed connect's instance is
  closed, as it already was before a connected one is handed over. If another
  process holds the name when the service starts, the first create fails (it
  insists on a new name), and the service tries again, waiting 1 s and
  doubling to 60 s, logging once per series of failed attempts and once when
  serving again. It never serves under a name it did not create.
- **What never crosses the pipe.** The TOTP secret, `ui.secret` and approval
  ids. Device approvals are not listed, because they need no code.
- **Wrong codes on the pipe are limited** (NIST SP 800-63B 5.2.2). Five are
  free. After that the pipe takes one attempt per 30 seconds. After 100 in a
  row it takes none. A code accepted on any other lane resets the count.
- **`privatae-bastion tray`**: the person's icon and approvals window, run as
  them and drawn from the pipe. `service install` starts it at every sign-in
  through the HKLM Run value `PrivataeBastionTray`, and `service uninstall`
  removes that value. One tray runs per session. The tray checks that the
  pipe's server is the `PrivataeBastion` service process before it sends
  anything. The daemon's own tray stays as it was for a bastion that runs as
  the person; the service still shows none.
- **`stepup-enroll --console-only`**, for an installer's elevated step. The
  secret is shown only when standard input and output are a console. It is
  saved only in the system service's state: on Windows and macOS when the
  service is installed and the process has machine authority, on Linux when
  the process is root. Both checks run before a secret exists.
- **`release-anchor --host <name> (--host-ca <pem file> | --force)`**, with
  machine authority, for an anchor whose Host is gone, e.g. a Host on this
  machine deleted with its data and set up again. `--host-ca` is the new
  Host's CA. It is refused when that is the CA this box pinned for the host,
  since the same CA means the same Host, alive, and when this box pinned no
  CA to compare. `--force` skips that check and is taken only on a console;
  an installer never passes it. All of this is checked before anything
  changes. It drops the anchor if it is that host and refuses any other.
  It unpairs that host. It renames that host's DCN state (key pin, factor,
  grants) to `dcn/<host>.released-<time>`, so a new Host under the same name
  starts clean. It succeeds when there is nothing left to release. After it,
  `pair` and `claim-anchor` work for the new Host.
- **A step-up code is spent only when the approval lands.** Approving a
  request checks the code, records the approval and marks the request
  approved under one lock, reading the request again before it is marked. A
  request answered meanwhile (another process shares the files, not the
  lock), or an approval that cannot be saved, withdraws the approval and
  gives the code back, unless a newer code was spent meanwhile. The code is
  recorded as spent before the approval exists, so no crash leaves an
  approval on a code that still works.
- **`service install` on Windows reads where Program Files is from HKLM**
  (`ProgramFilesDir`, the 64-bit view) instead of `%ProgramFiles%`, which an
  elevated process inherits from the elevating account's own environment.
- Approvals from an Administrator terminal and from the admin page work as
  before.

## 0.52.1

- **The device fingerprint is sent under a second name to a Host with no
  platform.** A pairing with such a Host (`--redeem-url unix://…` or
  `https://…`) sends an operator certificate request that carries the
  fingerprint as two URI SANs: first under the original device-fingerprint
  URN prefix (`fpSANPrefix` in pair.go), then `urn:privatae:hwfp:<fp>`, which
  that Host reads. A platform pairing's request names it once, under
  `fpSANPrefix`, as before: the platform signs a request with that one name
  and refuses one with any other. A signed accounting verifies with the
  fingerprint under either name, and a signer certificate that names two
  different fingerprints is refused rather than resolved.

## 0.52.0

- **A Host with no platform can own the bastion on its own machine.**
  `pair --redeem-url unix:///run/privatae-host/enroll.sock <token>` redeems the
  token over the Host's enroll socket (`POST /bastion/enroll/redeem`, the
  platform redeem's body) instead of `api.privatae.ai`. The pairing records
  transport `unix` and the lane socket and runs directory the Host names, both
  of which must sit inside the directory of the enroll socket. The redeem URL
  names a socket path only: a host, a port or a relative path is refused
  before the token is read. The Host's CA is pinned the way the platform's is,
  and a `pair --replace` that brings a different CA is refused.
- **Its lanes go over the Host's lane socket.** A unix pairing runs every lane
  that goes to the host's `:8443` over the tunnel (egress, management, the two
  parked harness workers, sessions, git, the heartbeat) over the lane socket
  instead, with the same mutual TLS, bearer and protocol. A pairing with no
  bearer opens no lane. It has no inference or service-slot forwards and no
  endpoint rotation, which all need the tunnel. Platform pairings run exactly
  as before.
- **A coder run of a Host on this machine is a socket.** Its control plane is
  served at `<runs_dir>/<run_id>.sock`, 0660, group `privatae-host` (root, with
  the reason logged, when the group does not exist), in place of a tunnel
  port. Only the owning pairing's directory gets it, every connection passes
  the run port's checks, and it is removed at run-down and when the watchdog
  stops the run. Run-up's answer carries `control_socket`. The socket is made
  only in a runs directory root alone can change: a real directory owned by
  root that nobody else may write, under directories that are root's and
  either writable by nobody else or sticky. The Host names the runs directory
  and writes the shared one, and the socket is chmod-ed and chown-ed by path,
  so a directory the Host could change would let it swap the socket for a link
  to any file on the machine and get that file. A socket is opened only for a
  run that is the pairing's and still up at that moment.
- **The `workspace` engine, and images from where the owner says.**
  `workspace` joins the engines a run may name. `coders set --image-prefix
  <registry/path/>` sets where run images come from (`default` resets it to
  `git.privatae.ai/privatae-harness/`, so machines that never set it are
  unchanged). Run-up now takes only `<prefix>harness-<engine>@sha256:<digest>`,
  the engine's own image, and pull credentials only for the prefix's registry.
- **An image built or loaded on the machine runs without a pull.** Docker's
  classic image store keeps no repo digest for such an image (measured on
  Docker 29.1.3: after `docker load` and after `docker build`, inspecting
  `<repo>@sha256:<id>` fails and `run` tries to pull; the containerd store
  keeps one and needed no change). Run-up now starts such a run from its image
  ID, when the image with that ID carries a tag of the named repository. The
  ID is the digest of the image's config, which names every layer by its
  content's digest.

## 0.51.0

- **Coder runs can no longer take the memory, CPU or GPU the machine itself
  needs.**
  Run-up used to start a run whenever fewer than `max` were going and free
  memory covered one run's limit. Runs that start together all see the same
  free memory before any of them has grown, so on a 3.7 GiB machine twelve
  512 MiB runs started, together left it 0 MiB free, and sshd stopped
  answering until the machine was rebooted. Now:
  - Run-up adds this run's limit to the limits of the runs already going and
    answers `full` when the total is more than the machine can spare: its
    memory minus GKE's node reservation (25% of the first 4 GiB, 20% of the
    next 4, 10% of the next 8, 6% of the next 112, 2% above 128 GiB) and a
    100 MiB eviction threshold. It also answers `full` while the machine is
    stalling on memory (PSI memory "full" avg10 at 60% or more). The `full`
    answer adds `mem_budget_mb`, `mem_committed_mb` and `mem_pressure`.
  - A watchdog in the daemon looks every 2 s and stops the newest running run
    when the machine has under 100 MiB free, or when memory pressure has stayed
    at 60% or more for 30 s (systemd-oomd's defaults), then waits 10 s before
    pressure may stop another. While the run it stopped last still has
    processes, it stops no other for up to 10 s, so a slow exit does not turn
    one stop into two. It kills the run through its cgroup
    (`cgroup.kill`), so it never waits on a container runtime that is slow
    for lack of memory, and keeps the run's record: run-down and run-status
    say why in `stopped_by`. On a cgroup v1 or hybrid machine, or a kernel
    without `cgroup.kill`, it stops the run through the runtime instead, and
    run-up counts such a run at its limit until the run is gone.
  - `coders on` sizes `max` from the same budget instead of keeping a flat
    2048 MiB for the machine, `coders status` shows the budget and how many
    runs fit in it, and the heartbeat's coders block adds `mem_budget_mb`.
  - CPU: every run starts with `--cpu-shares 2`, the lowest share (cgroup v2
    `cpu.weight` 1; the machine's own services sit at the default 100), as the
    kubelet gives a BestEffort pod. A run still uses any CPU nothing else
    wants, up to `--cpus`, and yields it whenever the Host, sshd or anything
    else on the machine needs it.
  - GPU: a run gets none. It has no `--gpus` and no `--device`, and starts with
    `NVIDIA_VISIBLE_DEVICES=void`, so a machine whose default container runtime
    is NVIDIA's exposes no GPU to it either, even from an image built on a CUDA
    base. Where the toolkit's config sets `swarm-resource`, the toolkit reads
    the names listed there first, so a run sets each of them to `void` too.

## 0.50.1

- **Coder runs pass `PRIVATAE_*` names for the run's id, its control
  capability and its two sockets** (`PRIVATAE_RUN_ID`,
  `PRIVATAE_HARNESS_CAP`, `PRIVATAE_HARNESS_CAP_ENFORCE`,
  `PRIVATAE_SIDECAR_CONTROL_SOCK`, `PRIVATAE_SIDECAR_EGRESS_SOCK`). The
  harness images published with this release read these names first.

## 0.50.0

- **Coder mode: a host can place coding runs on this machine, one container
  per run.** Linux only, with the bastion running as root, and off until the
  owner turns it on. `privatae-bastion coders set [--max N] [--mem MB]
  [--cpus F] [--engines a,b|all] [--allow-lan host[:port],...]` sizes the
  machine (at most 1 to 100 runs, 512 to 65536 MiB and 0.25 CPUs up to the
  machine's count per run, engines from codex, cursor, grok, claude-code,
  opencode, kimi and antigravity) without switching anything on. `coders on`
  fills what was not set: 2048 MiB and 2 CPUs per run (the machine's CPU
  count when it has fewer than 2), every engine, and as
  many runs as fit in the machine's memory less 2048 MiB, refusing when not
  even one fits. `coders off` stops new runs; runs already going continue
  until they are stopped or reaped. `coders drop [--host <host>]` takes back
  the standing coder grant of every host, or one, and stops their runs.
  `coders status [--json]` shows the settings, the grants and the runs.
- **The heartbeat says when this machine takes coder runs.** It carries the
  `coders` capability and a `coders` block (the limits, how many runs are
  going and how many are this host's, the grant's limit, memory, CPUs, the
  architecture, the container runtime and the engines) only while this
  machine would accept a run from that pairing: Linux, root, coders on, a
  container runtime, the pairing allowed the `harness` family, and on an
  anchored machine a valid coder grant. Otherwise both are absent, never
  empty.
- **Three verbs on the harness lane, mode `coder`.** `run-up` checks the
  request (run id, engine, an image `git.privatae.ai/privatae-harness/
  harness-<name>@sha256:<digest>`, the engine's uid 10001 to 10099, a
  credentials folder `/home/privatae/.<name>`, at most 1 MiB of credentials,
  the run's control capability, `max_minutes` 1 to 1440, default 240),
  pulls the image only when its digest is not here, with a throwaway
  registry config holding only this run's credential, starts the container
  and answers as soon as the run answers `/health` on its control socket
  (within 60 seconds), so no harness worker is held for the run's length. A
  run that does not fit (the machine's limit, the grant's limit, free memory
  or a free port) gets `ok`, exit 0, `started: false`, `reason: "full"`: a
  capacity answer, never a refusal, so a burst does not trip the quarantine.
  `run-down` reads the container's `memory.peak` and `cpu.stat`, stops it,
  confirms it is gone, removes its files and reports peak memory and CPU
  seconds (both null once the container has exited, since they are read
  through its running process), wall time (null when the run has no
  record), whether it was OOM killed (null on nerdctl, whose inspect does
  not report it), its exit code and how many egress requests were refused.
  On an anchored machine only the host that started a run, or the anchor
  host, may stop it; on a local machine any paired host may. A container without this
  run's `privatae.coder.run` label is never stopped. `run-status`
  lists the pairing's runs (every run, for the anchor host).
- **Each run is a hardened container.** No network (`--network none`),
  every capability dropped, `no-new-privileges`, the seccomp profile the
  platform's own harness pods run under (`seccomp-personal.json`, built into
  the bastion and pinned by its SHA-256 in a test), a read-only root, the
  engine's uid, memory with no extra swap, CPUs, 4096 processes and a `/tmp`
  tmpfs the size of the run's memory. Its workspace, home and control folders
  are owned by the engine's uid, mode 0700, and its credential files 0600.
  Its deadline is `max_minutes` plus 15 minutes; past it the tunnel port
  refuses and the reaper removes the run.
- **A run's only way out is `egress.sock`.** One proxy per run, a unix socket
  owned by the engine's uid, mode 0600, taking HTTP CONNECT and absolute-form
  plain HTTP. Anchored or not, it refuses loopback, private, CGNAT,
  link-local (the cloud metadata address included), ULA, multicast, reserved
  and unspecified addresses, the IPv6 forms that carry an IPv4 address and
  site-local `fec0::/10`,
  `localhost` names, names that do not resolve and a name with even one such
  answer, and any address this machine takes as its own (see below). It
  dials only the addresses it vetted, IPv4 first, never the name again. A LAN
  host passes only when the owner named it in `coders set --allow-lan`.
  Destinations are never logged; refusals are counted on the run.
- **The host reaches a run through one tunnel port per run, 18200 to 18299,**
  on the owning pairing's tunnel only, joined to the run's `control.sock`.
  Every connection is checked when it is accepted: the pairing still holds the
  `harness` family, the run is that host's and within its deadline, and the
  connection comes from that host's own tunnel address. The socket's inode is
  pinned and its far end must be the engine's uid.
- **A reaper removes runs nobody holds.** At start and on every heartbeat
  reply it removes a run past its deadline, one whose host is no longer
  paired, one that stopped (exited or missing) more than 600 seconds ago,
  and one older than 120 seconds that two replies in a row listing
  `coder_runs` left out. The 600 seconds count from the exit time the
  container runtime reports or, when it reports none (the container is
  missing, or the runtime keeps no exit time) or one later than now (the
  clock stepped back), from when the reaper first saw the run not running;
  such an exit time keeps counting from that sighting once the clock passes
  it. That first sighting is kept in memory, so a restart of the bastion starts
  those 600 seconds again. When the
  container runtime does not answer the listing, it skips that round rather
  than read every run as exited.
- **On an anchored machine a standing coder grant replaces the per-run
  approval.** `coder_grant_sync` installs a grant signed with the pinned key,
  of kind `coder_grant`, for this server and for the host that sends it, naming
  its engines, at most how many runs (1 to 100) and an expiry within its
  approved days; the person approves it once, here. `coder_grant_drop`, the
  host leaving a grant out of two heartbeat replies in a row, or `coders
  drop` takes it back, and a drop is never held back. Both ops are in the
  `harness` family. `run-up` and `run-down` still honour the quarantine;
  `run-status` is a read. The enforcing report lists the coder grants held.
- **This machine's own addresses, on every lane that dials for someone
  else.** A destination is this machine when it is on one of its interfaces
  (a public address included) or, on Linux, when the kernel's routing table
  delivers it here: any route type but unicast (`local`, as for an AnyIP range
  on `lo`, broadcast, anycast, multicast), asked of the kernel per connection.
  The IPv4 address inside an IPv4-mapped, NAT64 or 6to4 address is checked
  too, and when the machine cannot tell, it refuses. A public address that
  reaches this machine only through a 1:1 NAT in front of it is not caught.
- **The anchored egress lane refuses destinations that are this machine.**
  Before, on an anchored machine it refused only the internal ranges
  (loopback, private and ULA, link-local, CGNAT, multicast, unspecified and
  reserved, also inside a NAT64 or 6to4 address); it now also refuses this
  machine's own addresses, by address and by name, with no exception. A
  local (unanchored) machine's egress lane is unchanged and vets no
  destination.
- **The backup lanes refuse destinations that are this machine.**
  `backup_fetch` and `backup_push` refused only loopback, private,
  link-local, multicast, unspecified, CGNAT and ULA addresses. They now also
  refuse this machine's own addresses, for every address the URL's name
  resolves to, each redirect a fetch follows and the address dialled.
- **The backup lanes classify an address as a coder run's proxy does.**
  `backup_fetch` and `backup_push` read the IPv4 address inside a NAT64
  `64:ff9b::/96` or 6to4 `2002::/16` address and refuse it when that IPv4
  address is internal, so `64:ff9b::a00:1` and `2002:a00:1::1` (10.0.0.1) no
  longer pass. They also refuse IPv4-compatible `::a.b.c.d` and
  IPv4-translated `::ffff:0:a.b.c.d` addresses, the rest of `64:ff9b::/32`,
  site-local `fec0::/10`, `0.0.0.0/8`, `198.18.0.0/15` and `240.0.0.0/4`;
  before, all of these passed except `::`, `::1` and `0.0.0.0`. This is a
  tightening: a backup URL that resolves to any of them, or a redirect or
  dial to one, is refused now.

## 0.49.0

- **The anchor host can run root commands, under one grant given at the
  machine.** `sudo -H privatae-bastion root-exec grant --host <anchor host>
  --for 30d` shows what it grants, asks for the code from the authenticator
  enrolled here, and lets that host run commands as root on this machine one
  at a time, with no approval per command, until the time chosen.
  `privatae-bastion root-exec` shows the grant and `root-exec revoke` takes it
  back. The grant is written only by that command: nothing the host sends can
  create, widen or extend it, a member pairing never holds it, and the
  `session` family switched off here stops it.
- **One command per frame on the session lane.** The host sends the session
  lane's `S` frame with op `session:root:exec`, the command, a deadline and an
  output size; the bastion answers `J` with stdout, stderr, the exit status,
  the duration and whether anything was cut, then `X`. The command runs as
  `/bin/sh -c` in its own process group with a plain root environment and no
  input; its deadline (default 10 minutes, at most 8 hours) and the host
  closing the socket kill the whole group: SIGTERM, then SIGKILL 2 seconds
  later whether or not the shell has already gone, so a child that ignores
  SIGTERM does not outlive it. The grant, the local switch and the quarantine
  are checked again every 2 seconds while a command runs: a revoke or an
  expiry stops a command already running, answered with 126 and a `J` whose
  `stopped` says why. That stop kills the command's whole cgroup too, so a
  child that left the process group (`setsid`, a double fork) does not keep
  running as root after the grant is gone. Each stream returns at most 256 KiB
  unless the host asks (at most 4 MiB), keeping its start and end and stating
  how much was cut. An older bastion refuses the frame as not a session op.
- **Every root command is recorded here.** The command and its whole output
  (up to 64 MiB) go to `sessions/<id>.log` in the context store, and the audit
  file gets a start and a stop row with the command, its sha256, the exit,
  the duration and the byte counts. Every other outcome gets a row too, with
  the command: a refusal, a bad command or session id, a transcript that would
  not open, a command that would not start.
- **The bastion records where each root command connects.** On Linux each
  command starts in a cgroup of its own, and an nftables table the bastion
  creates for that command (and removes when it ends) records every
  connection the command and its children open: destination, protocol, port
  and how often. The table only records; it never changes what the machine's
  own firewall allows. The `J` frame gains `untrusted_connections`: the
  destinations outside the platform's own hosts, at most 32, the rest counted
  in `untrusted_connections_more`, and absent when there were none, so an
  older host reads the frame as before. A host that reads it treats the
  output as untrusted and ends root for the turn. The platform's own hosts are
  listed in `platform_hosts.json` in the bastion's config folder (addresses,
  CIDRs, names); with no list, every connection off the machine counts as
  outside, and loopback never does. A command whose connections could not be
  watched (not Linux, no `nft`, no cgroup of its own) gets one entry, `*`, that
  says why. Every connection, the platform's marked as such, goes into the
  transcript and the audit stop row. Connections another program makes for
  the command (dockerd pulling for `docker build`, a unit `systemctl` starts)
  are not the command's and are not seen.

## 0.48.0

- **On macOS and Windows a networked bastion runs as the system's service.**
  A process the signed-in person started is one they can stop, which is
  right on their own computer and wrong on a machine an organisation enrols.
  `install.sh --networked` on macOS now installs a launchd daemon
  (`ai.privatae.bastion`) running as root, and `install.ps1 -Networked` a
  Windows service (`PrivataeBastion`) running as LocalSystem. Both start at
  boot, before anyone signs in, and come back after they stop: launchd's
  KeepAlive on macOS, and on Windows a restart five seconds after any failure,
  which also covers the exit after a self-update. `privatae-bastion service
  install|uninstall|status` does the same by hand and needs machine
  authority. Linux is unchanged: its service is still the systemd unit.
- **The service's program can be replaced only by root or an administrator.**
  On macOS the installer puts it in `/Library/Application Support/privatae/bin`
  with a link on `PATH`, and `service install` refuses a program that a
  non-root user owns or that a group or everyone can write, or that sits in
  such a folder (`/usr/local/bin` belongs to the signed-in user on many Macs).
  On Windows it goes in `Program Files\Privatae`, and a program anywhere else,
  including the per-user install folder, is refused.
- **An administrator's commands act on the service's state.** With the service
  installed, a command run with machine authority (`sudo` on macOS, with or
  without `-H`, or an Administrator terminal on Windows) reads and writes the
  state the service uses: root's home on macOS, LocalSystem's profile on
  Windows, which only SYSTEM and administrators can open.
- **No second bastion from an ordinary account beside the service.** With the
  service installed, `pair`, `run` and `status` from an account that does not
  administer the machine are refused with a sentence saying what to do. This
  binds a cooperating binary only. An administrator's `run` beside a running
  service is refused too, because it would hold the same pairings and bring
  up the same tunnel: on Windows by the existing run lock, and on macOS by a
  lock the daemon now takes in its state folder. A Mac without the daemon
  takes no lock and behaves as before.
- **As a Windows service there is no tray, no dialog and no detached
  relaunch.** A service has no desktop: a dialog would wait for ever where
  nobody sees it, and a relaunch would be a second bastion beside the one the
  service manager restarts. What the service prints, a crash included, goes
  to `bastion.log` in its state folder, set aside once it passes 8 MB. A
  fresh service waits for its first pairing instead of failing every few
  seconds. The macOS daemon's log is root-only and set aside at the same size
  when the daemon starts.
- **The Windows installer's -Networked run** checks for an elevated terminal
  before downloading anything, stops a running service before replacing its
  program, removes the logon task an earlier install registered and stops any
  bastion still running from a per-user install, and adds the program's folder
  to the machine's `PATH` as the registry stores it, leaving every
  `%VARIABLE%` entry unexpanded. Pairings made by a per-user install are not
  carried over; the machine is paired again.
- **The macOS installer prints the anchor command with the program's full
  path,** not the name on `PATH`, which may belong to the signed-in user.
- **On a Windows service the folder's agent runs as the folder's owner, never
  as LocalSystem.** The Windows form of the unix drop: the owner is read from
  the folder's security descriptor and refused when it is SYSTEM, a service
  account, a group such as Administrators (the usual owner of what an elevated
  administrator made), a built-in account such as the Administrator or Guest,
  or not a person's account at all. The agent is started under the owner's own
  token from their signed-in session, so it runs while they are signed in and
  the store card says so when they are not; starting it for an owner who is
  signed out needs a token made without their password, which is not built. The
  owner is given access to their store's state leaf, its public cert and the
  runtime by a permission entry. The leaf's entry is set only while the leaf is
  empty or found already right: a leaf holding another account's state is left
  as it is and named. Nothing is written into the person's folder: the agent's
  directory stays in the bastion's state. The child's environment names the
  owner's profile rather than LocalSystem's, and its log must be a plain file
  with one link.
- **Not yet, and said so in the code:** on a Windows service the signed-in
  person's `context` cannot reach the bastion, because the named pipe it
  would use is not built; folders are added from an Administrator terminal.

## 0.47.3

- **The lane addresses are read under their PRIVATAE_* names only.** The local
  inference, sterilizer and bastion agent lanes come from `PRIVATAE_LLM_ADDR`,
  `PRIVATAE_PII_ADDR` and `PRIVATAE_BASTION_AGENT_ADDR`, `_CERT`, `_KEY` and
  `_CA`. Their older spellings are no longer read, so a lane set under one
  stays off until it is renamed in the bastion's unit environment. The
  installers set none of these.
- **The source carries the product's own name.** Comments, tests and this
  changelog no longer use the platform's former internal name. A test fails on
  it anywhere outside the few identifiers the host and its harness image still
  use: the delegation tag variable, the harness image's three variables and
  workspace path, and the device-fingerprint prefix in the pairing request.

## 0.47.2

- **A move to a new Hub key is not held back by an old failure.** A host can
  move its machines to a new Hub key on the same relay entries. The bastion
  remembered failed probes per entry, so a dead spell under the old key could
  hold the move back for up to a day, and a probe of a key the Hub did not
  answer yet could keep the machine off its preferred entry. A failure is now
  remembered for the entry and the key that was tried.
- **A move whose save failed is saved on a later beat.** When the bastion
  moved to a new entry or key but could not write it to its pairing file, the
  file kept the old ones and nothing tried again, so a restart came up on the
  old key. Once the host retires that key the machine could no longer reach
  it. The save is now retried every minute until it lands; a pairing whose
  file was removed is not brought back.
- **A host paired again keeps the entry and key it was given.** After
  `pair --replace` (or `unpair` and `pair`) for a host the running daemon
  still serves, the daemon could write the old pairing's entry and Hub key
  into the new pairing's file, which would then start on them. It now writes
  nothing into a pairing file that holds a different WireGuard key.
- **The heartbeat says when a move is not saved yet.** Each beat now carries
  `endpoint_save_pending`: true while the bastion runs on an entry and Hub key
  it moved to but has not managed to write to its pairing file, false
  otherwise. A host can then keep the old Hub key while any machine says true,
  so a machine whose save keeps failing is not stranded at its next restart. A
  pairing started again from its file reports only its own moves.
- **A pairing made again comes up without a restart.** `pair --replace` run
  from a shell (or `unpair` and `pair`) while the daemon runs wrote new
  credentials that the daemon did not use until it was restarted. The daemon
  now notices on its next check, every 15 seconds, that the pairing file holds
  a new WireGuard key, and restarts that pairing's tunnel and lanes from it.
- **A stopped pairing writes nothing to its file.** A heartbeat stuck on a
  dead tunnel could come back after its pairing was stopped and started
  again, and save the stopped copy's older entry and Hub key over the new
  ones. Nothing is written from a stopped pairing any more.
- **No change to the program:** the README's table of how each claim is
  tested cites one test per row again, so `deploy/check-claims.sh` passes.

## 0.47.1

- **No change to the program.** Comments and test data added since 0.43.1
  no longer name our own machines, repositories, design notes or the
  platform's source files; one older test uses neutral sample data and one
  older test comment no longer names a platform file. Every check the tests
  make is unchanged.

## 0.47.0

- **A backup key can live on this bastion.** A host encrypts its backups to
  its recovery key, which its owner keeps, and to any bastion keys registered
  with it. `privatae-bastion backup key init` makes an X25519 key here, kept as a standard age key file (0600) in
  the bastion's state folder, and prints the three fields to register on
  your host: kind `bastion`, a label (this machine's name unless you give
  `--label`), and the public key. The host then encrypts its backups to it too.
  Only the public half ever leaves this machine. `--replace` makes a new key
  and keeps the old one, which still opens the backups made with it; `backup
  key show` lists both.
- **A host restores one backup only after you approve it here.** A host that
  restores a backup asks this bastion for that backup's own key
  (`backup_reseal`). The request waits in `privatae-bastion backup requests`
  until you answer it with `backup approve <id>` or `backup deny <id>`;
  approving asks for your authenticator's code when one is enrolled here.
  The key held here opens the backup's sidecar, the sidecar is checked to be
  the backup it names, and the same record is sealed to the requesting
  host's own key alone. A request is bound to the pairing it came in on and
  that pairing's host number, and a sidecar of another host's backup is
  refused, whatever the request calls itself; restoring a lost host's
  backups onto its replacement is `backup restore-plan`, at this machine.
  A sidecar may name a backup kept in platform storage (`b/`) or staged
  there for a copy kept only on a bastion (`s/`). Before you approve,
  `backup approve` shows the pairing and its host number, what the host
  says, and what the sidecar itself says, opened here (host number, when it
  was made, which backup). A host can hold at most 16 requests, or
  512 KiB of them, waiting here; answering one frees its room at once, and a
  request lapses after a day. The request file is locked while the daemon or
  `backup approve`/`deny` changes it, so neither loses the other's change,
  and a request file that cannot be read is set aside (and named by `backup
  requests`), never overwritten. A host's label is refused if it holds any
  control or formatting character. A
  sidecar whose `made_at` is not a time is refused, and everything shown
  from a sidecar is quoted.
  `backup reseal` does the same offline. The owner can also do this in their
  browser with the host's recovery key.
- **Your backups held here, listed and sent back.** `backup_list` tells a
  host which backups this machine holds for it, with the sizes and SHA-256
  of each data file and sidecar; a digest not yet known is read in the
  background and appears on a later listing, so a listing never waits on a
  large file; a read that does not return within two minutes (a mount that
  stopped answering) holds up no other folder's digests. The two minutes
  count from the last read of the file that returned, so a large backup on a
  slow disk that keeps answering never counts as stuck and refuses no push
  from its folder. `backup_push` sends one of those files to a short-lived https
  upload address the host gives: only a file named like a backup, directly
  in the host's own backup folder or a folder you shared with it, through no
  link that leaves it; checked against the SHA-256 the host named before a
  byte is sent; never to this machine's own network or through a redirect.
  The header the upload address was signed with (`headers`, as the
  platform's `backup.put_url` returns them: `If-None-Match: *`, so storage
  never writes over an object that is there) goes on the upload. It is the
  only header a host may hand over, and only with that value: any other
  header name or value is refused before a job starts, and so is a start
  with no headers at all (the platform always hands that one over).
  `start` answers at once and the check runs in the job; a job whose file
  stops answering for two minutes (a mount that died mid-push) fails with a
  sentence and its upload is stopped. A push waiting for its turn to read
  (behind a stuck read) is not a read: after two minutes of waiting it fails
  with a sentence saying what it waited on (its folder's stuck read, or the
  cap), never one blaming a folder that answers. Pushes and the background
  digests keep one record of reads that have not returned: a folder holds at
  most one stuck push read and one stuck digest read however often a push is
  started there, and the bastion at most eight of both together; a push is
  not started in a folder with a read of either kind that has not returned,
  the digests skip a folder whose push read has not returned, and neither
  starts while eight reads have not returned. A listing creates
  nothing: the host's backup folder is made by the first backup op that
  writes. Every folder is read with the same two-second bound as the host's
  own: a shared folder on a mount that stopped answering, or one that now
  reaches this bastion's own state, is left out of the listing and named
  under `unavailable`, and a push from it is refused with a sentence.
- **Sharing a lost host's backups with the host that replaces it.**
  `privatae-bastion backup share --with <new host> --from <lost host>` (or
  `--dir <folder>`) lets the new host list and ask for the backups in that
  folder, as `shared/<name>`; it cannot write there. `backup shares` lists
  them, `backup unshare` takes one back. Only a command at this machine
  changes this. A share belongs to a host, not a folder, and goes when that
  host is unpaired or revoked.
- **One backup folder per host.** A backup op is refused while a host's
  backup folder is the same as, inside, or contains another paired host's;
  is or contains this bastion's configuration folder, backup keys or backup
  records; or sits inside the configuration folder anywhere but under its
  `backups` folder, where the default `backups/<host>` is.
  Upgrading: if two paired Hosts share a backup_root (or nested folders),
  backup copies to this machine stop until each Host has its own folder.
- **Ops cannot touch a host's backup folder.** Every pairing's backup folder,
  wherever you put it (a NAS mount too), joins this machine's own record: no
  op or action-op verb may name it, anything in it or a folder holding it,
  and the sandbox hides it. A backup folder on a network mount that stops
  answering does not stop op runs: when checking it fails or takes more than
  two seconds, a run goes on without its mask (the run's closed view still
  covers it), no op may name it all the same, and the log says so once. The
  same two-second bound applies when a backup op checks that each host's
  folder is its own: another host's stale folder blocks nothing (it is
  compared as written and as it last resolved), and a host whose own folder
  does not answer has its backup ops refused until it does. The last place
  each backup folder resolved to is kept, so during an outage an op still
  cannot name the real place.
- **The backup folder is thinned, only among what this bastion fetched.**
  Backup files (`<stamp>.tar.zst.age`, `<stamp>.key.age`) fetched through
  `backup_fetch` land at the top of the host's backup folder, and this
  bastion records each one (arrival time, size, SHA-256) in its own state
  folder. After each arrival the folder keeps the newest 7, and the newest of
  each of the last 14 days, 8 weeks and 12 months, by arrival, among the
  recorded files still as they arrived. A file you put there, or one from
  before this version, is never removed. A `.keep-all` file turns it off.
- **Jobs are each host's own.** Fetch and push job ids are random, a status
  call answers only the host that started the job, and no reply or job error
  quotes an upload or download address's signature.
- **Restoring a lost host.** `backup restore-plan --dir <folder>` lists the
  backups in a folder and reseals the one you choose to the key of the host
  that replaces the lost one. What running that host on your own hardware
  needs, which this program does not provide, is listed in the README.
- Built with filippo.io/age 1.3.2 for every encryption here; golang.org/x/crypto,
  x/sys and x/net move up with it.

## 0.46.0

- **Test data names no machine of ours.** The tests and the action-op example
  used our own folder layout, forge, images and service names as sample data.
  They now use neutral ones (`/opt/acme`, `forge.example.com`, `acme-web.service`);
  every check they make is unchanged. No change to the program.
- **Action ops: ship steps run as ops.** An op with `kind: action` builds,
  pushes, moves a tree, restarts a service or rolls a workload, in two parts:
  - **Its program runs unprivileged.** Each run gets a uid no run had
    before, in its own systemd transient unit, with no capabilities and no
    new privileges. It sees
    what a files op sees, with the machine read-only and a private work
    folder at `/tmp`.
  - **Its network, in an apply, is held to the destinations it declares:**
    to their addresses by the unit's allowlist, and its TCP to their ports by
    Landlock, which also blocks abstract unix sockets and signals out of the
    sandbox. UDP is held to the addresses only. A destination on this
    machine, a link-local address or a cloud's metadata service is refused.
    **A dry run has no network.**
  - **No memory ceiling; the op goes first.** A run uses what the machine
    has to spare. It is stopped first when the machine runs short, and says
    why:
    - when free memory falls to a floor above the kubelet's eviction line;
    - when the machine's own services start waiting on memory, 7 points more
      than the least they had during the run;
    - and the kernel kills it before anything else if it must kill.
  - **Root work is done by the bastion itself**, as four verbs the manifest
    declares with fixed arguments:
    - `tree.checkout` moves a git tree forward only, to an exact commit,
      with no hooks. It works only in a tree whose `.git` only root can
      change, and never writes into a folder another user controls. It never
      overwrites an ignored file. It refuses local changes
      and any git config that could run a program.
    - `unit.reload` and `unit.restart` act on one service.
    - `k8s.set_image` rolls one container, only forward:
      - to a digest this machine holds a receipt for, from the repository
        the manifest names;
      - from the commit behind a live image this machine itself rolled.
    - `logs.check` returns a verdict and one line, after the apply.

  The dry run lists every verb with the state it moves from. The apply is
  refused before anything runs if that list changed.
- **Sealed credentials.** Each machine now has an encryption key, which the
  heartbeat carries signed by the machine's own key. An action op's declared
  credentials arrive sealed to that key and bound to the run. They exist only
  in the program's environment and on the run's own tmpfs, are scrubbed from
  its output, and are never handed to a dry run. A credential a verb names
  goes to the verb and never to the program.
- **Receipts.** What an action op's program reports it pushed becomes a
  receipt: a DSSE envelope signed by this machine, naming the op, its
  parameters, the image, its digest, its source and its commit. The first
  receipt for a digest stands; a conflicting one is refused.
- **The startup sweep.** A run cut short by the bastion's own restart leaves
  a mounted tmpfs, a work folder or a unit behind. The next start removes
  all three.
- **Fixed: an op run as a user could not write `/dev/null`.** The sandbox's
  device nodes were made with the umask applied (0644). They are 0666 now.
- **The heartbeat says whether this machine can run action ops**
  (`action_ops`, with the reason when it cannot), and carries
  `encryption_key`.
- **One approval for a whole ship.** Your device signs one plan listing every
  step of a ship, and each machine runs only its own lines of it, once. The
  device fills in each machine's key from its own pins (`pin-machine`,
  printed by the machine when you pin the device there), asks for your code
  when the plan runs root work (checked against the factor on the device's own
  pairing), and never signs such a plan with "approve all shown".
- **Each machine checks the plan itself:**
  - the device's signature, under a key pinned there;
  - the expiry, and a version that only goes up;
  - its own key in the plan;
  - that each line is its own and runs once;
  - that root lines come with your code;
  - that the held op declares exactly the verbs the line showed.
- **Receipts carry values between machines.** Every line ends in a receipt
  signed with the machine's own key. A roll takes its digest only from a
  successful earlier step of the same plan, at the plan's commit. The first
  roll on a machine can take the live image as its starting point, and the
  device says so.
- **Lines run in order.** A line runs only after every line before it
  succeeded, shown by their signed receipts, and only as many times as the
  plan allows. Its attempts run one at a time: the next only after the last
  failed, never after one passed or after an undo. The machine keeps this
  record itself; an attempt the bastion died in is settled as failed when it
  starts again, with a signed receipt saying so. A pod that lost an answer
  reads a line's receipts back with `op_plan_status`.
- **Undo** takes a step back, once, to the state its machine recorded before
  the step's first attempt. Each change is recorded before it is made, so a
  retry is taken back too. It needs a signed receipt that a later step failed
  its check on its last allowed attempt, or that the step's own latest attempt
  failed and none passed. A tree or workload something else moved since the line's
  changes were read — while its program ran, or between attempts — is left
  alone: the verb refuses it, so an undo never takes that change back. This
  holds for every action op's apply, in a plan or not. Changes this bastion
  makes to one tree or workload, forward or undo, take turns, and an undo
  reads its target again right before it writes. An op that moves the same
  tree or container twice is refused when it arrives. Every command a verb runs has a
  deadline, so one that never answers cannot hold a target for good. The state goes back first and a unit restarts
  after, and a file the machine keeps is never overwritten.
- **A roll whose image is already set still waits for its rollout,** so a
  retry after a rollout that timed out passes only once the rollout is done.
- **Nothing in a plan can hide what you read:** its fields are plain text,
  and the device refuses control characters, line breaks and direction marks.

## 0.45.0

- **An op sees only what it declared.** Until now an op's sandbox showed it
  the whole machine read-only, so a root op's dry run, which runs before
  anyone is asked, could read a credential file and hand it back to the host.
  Now an op sees the system's programs and libraries, a few `/etc` files that
  hold no secret (`passwd`, `hosts`, `resolv.conf`, certificates and the
  like), and the paths its manifest declares: its effects and a new `reads`
  list. Every other file and folder is covered with an empty read-only mount,
  and a cover that cannot be put in place refuses the run. Links are left in
  place (where one points can be read, not what is there), and the op's own
  mount table names the folders it was denied. A read on a mount the sandbox
  does not carry, such as a network share, is refused, as an effect there
  already was.
- **An op that reaches a credential store is refused.** The stores are:
  - `/root`;
  - `.ssh`, `.docker`, `.git-credentials`, `.kube`, `.gnupg`, `.aws`,
    `.netrc`, `.pgpass` and `.config` in any home;
  - `/etc/shadow` and `/etc/gshadow`;
  - `/etc/ssh`, `/etc/wireguard`, `/etc/privatae`, `/etc/letsencrypt`,
    `/etc/ssl/private`, `/etc/pki`, `/etc/systemd`, `/etc/credstore` and
    `/etc/docker`;
  - docker's, k3s's and Kubernetes' state;
  - PostgreSQL's and MySQL's data directories.

  You can add more, one absolute path per line, in `sensitive_paths` in this
  machine's own record. A path is judged as written and as it resolves, again
  at every run. The run judges exactly the list it hands the sandbox, so a
  link moved between the check and the run cannot slip a store past it. A
  bind mount or hard link you make yourself that puts a credential file
  inside a declared path is not caught: list that path too. Such an op waits
  for a later release that shows its dry run only on your own device.
- **The heartbeat says so** (`op_view_closed`), so your host knows which
  machines show an op only what it declared.

## 0.44.0

- **An update to a newer signed release no longer needs an approval on each
  machine.** On an anchored machine, a self-update your host asks for goes
  ahead without your approval when the version is newer than the one running.
  Our signature on the release, made on the key holder's own computer, is the
  approval, and the update still happens only when a signed manifest names
  exactly that version. Updating a fleet used to take one approval per
  machine. A move to an older version, or to one this build cannot compare
  with its own (an unstamped build, a suffixed version), still needs your
  approval bound to that version, because a signature shows that a release
  was published, not that it is the latest. An update from a member host is
  still refused, and switching `directives` off in the local console still
  refuses every update.
- The enforcing report carries `update_forward_needs_no_approval`, so the
  host learns the rule from the machine instead of inferring it from the
  version number, and asks nobody for a forward update. It is false on a
  build that cannot read its own version, which gates every update.
- A machine on 0.43.1 or earlier applies its own rule to this release, so it
  still needs one approval to move to 0.44.0. Updates to newer versions after
  that need none.

## 0.43.1

- No change in behaviour. The tests use documentation addresses and name the
  forge through the constant the git lane uses, and one sentence in the 0.43.0
  entry below is reworded.

## 0.43.0

- **A pairing that offers more than one tunnel address is refused.** The
  host's tunnel address in the pairing response becomes the WireGuard peer's
  only allowed address. It used to be taken as given, with `/128` added only
  when it carried no prefix, so a response naming a prefix wider than one
  address, or `::/0`, widened what the tunnel carried. The platform
  sends one bare address. Anything else is now refused when pairing, when the
  tunnel comes up and when its endpoint is rotated, and nothing is saved or
  configured; a single address becomes `/128` (or `/32`).
- **git's own store and cache helpers no longer keep the forge token.** git
  hands an approved credential to every helper it has, and a helper
  configured after `git-setup`'s lines, or in a repository's own config, kept
  the token. With git 2.46 or later, the credential helper now answers with
  a pre-encoded credential marked not to be kept, which git sends as the same
  header: git's own store and cache helpers keep nothing. A helper that
  records everything it is given still receives the token. A git
  older than 2.46 gets the username and password as before, and for it only
  helpers configured before `git-setup`'s lines are kept out.
- **Each security claim in the README names the tests behind it.** New tests
  cover the tunnel's allowed address, the listeners on the machine and in the
  tunnel, the absence of an MCP route, the allowlisted op's fixed argv, file
  handlers with no shell, observe ops that write nothing, no input injection,
  the self-updater's digest check, the terminal's root and approval walls,
  the machine-authority gates and the git helper.
- **A release can be checked from a clone of the public repository.**
  `deploy/verify-release.sh` used to check out the manifest's `built_from`,
  which names a commit in the repository the release was built in and is not a
  commit in the public one, so from a public clone it stopped with
  `invalid reference`. From this release on, each public snapshot carries the
  annotated tag `v<version>` with the line `built from <built_from>` in its
  message. The script checks out that tag when `built_from` is not in the
  clone, refuses a tag without that line, reports a failed tag fetch as such,
  and prints which source it used. The README and SECURITY.md describe it that
  way.

## 0.42.1

- No change in behaviour. The README describes what the bastion does as of
  this release: the approval device and the write gate on anchored machines,
  host-written ops and their sandbox, the service slot, and the commands that
  were missing from the reference. In the built-in help, the description of
  `claim-anchor --rotate` no longer sits under `--repin`.

## 0.42.0

- **The agent is read from its own name only.** The bastion fetches
  `privatae.ai/bastion-agent/version.json` and installs the
  `bastion-agent-<version>.pyz` it names. It no longer falls back to the legacy
  `privatae.ai/freeagent/version.json` or accepts the legacy
  `freeagent-<version>.pyz` entry. When the address cannot be reached, the
  installed agent keeps running, as before.
- The release script checks that the agent is signed at the address this
  version reads, and no longer at the legacy one.
- The README lists the names that keep the word freeagent on purpose (the
  state directory, the heartbeat fields, the agent's environment variables)
  and says when the legacy address is retired.
- **Fuzz targets for every wall a host's input goes through.** The path
  sandbox for store reads and move plans, an op's declared effects and path
  params, service slot names, the capability family each op needs, step-up
  requests, and every signed record and approval the bastion verifies each
  have a target that states the property the wall exists for
  (`client-go/fuzz_*_test.go`). `go test` runs their seeds;
  `deploy/fuzz.sh` runs each target for a bounded time. What they found is
  fixed below, and each finding is kept as a seed.
- **A store's excludes hold for the file that is opened.** A read or a move
  plan checked the grant's excludes against the text of the path the host
  sent. Three ways around that are closed:
  - Whitespace: the sandbox trims it before opening, so `" .ssh/id_rsa"` or
    `"server.key "` read the excluded file.
  - A link inside the store: with `keys` pointing at `.ssh`, `keys/id_rsa`
    opened `.ssh/id_rsa`. The excludes are now also judged on where the path
    leads.
  - Names the file system treats as the same: on Windows and macOS `.SSH` is
    `.ssh`, and on Windows `.ssh.` and `server.key::$DATA` name `.ssh` and
    `server.key`. Excludes compare names the way the platform does.
- **A store path that goes through a link that leads nowhere (or loops) is
  refused.** Nothing can be reached through such a link, and where it would
  lead cannot be shown to be inside the store. A broken link as the last part
  of a path is unchanged: a stat of it reads as gone, and a move renames the
  link.
- **An op's effect glob may not name anything under a system folder.** The
  refusal of `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, `/var/tmp` and `/boot`
  compared the effect as literal text, so `/b*/*` (which names
  `/boot/vmlinuz`) passed. A glob is now judged segment by segment, the way it
  already was against the machine's own record. A shallow glob such as `/*/x`
  or `/var/*/x` is therefore refused, because it could name `/boot/x` or
  `/var/tmp/x`; name the folder instead (`/srv/*/x`).
- **A device approval with a line break inside its purpose or nonce is
  refused**, and the device will not sign one. The signed bytes join the
  fields with line breaks, so such an approval could be read with part of its
  purpose moved into its nonce. The purposes the bastion builds never contain
  one, so no approval it asked for is affected.
- The test suite compiles for Windows and macOS again: three tests that use
  Linux-only parts of the op sandbox moved to `ops_linux_test.go`, so
  `GOOS=windows go vet ./...` and `GOOS=darwin go vet ./...` pass.

## 0.41.0 (not published)

*0.42.0 was merged before this was published, and carries these changes.*

- **Release manifests are signed, and the bastion checks the signature.** The
  bastion's own manifest and the agent's are each published with a signature
  file beside them (`version.json.<first 16 hex of its sha256>.sig`), an
  ed25519 signature over a short statement: what was released, its version,
  and the manifest's sha256. The public keys are compiled in
  (`release_sign.go`). A self-update, the update banner and the agent download
  all refuse a manifest that does not verify. Before this, the digests came
  from the same server as the files they checked, so anything that could
  change one could change both.
- The release key never reaches the machine that builds and publishes. A
  release is built, then waits until the key holder signs it on their own
  computer with `deploy/release-sign` (the key is stored encrypted under a
  passphrase), and is published only when that signature verifies against the
  keys this release pins and the keys of the release the fleet runs now. A
  release must pin two keys, a primary and an offline spare, so losing one
  strands nothing.
- The agent is never replaced with an older version than the one installed. A
  signature proves a manifest was published once, not that it is current, so a
  replayed older manifest is kept from moving the agent backwards.
- The manifest and the signature are each fetched with a 20-second limit and
  read at most 1 MiB. The agent's manifest was fetched with the two-minute
  limit meant for binaries.
- **Release builds are reproducible.** `deploy/build.sh` pins the Go image by
  digest and builds with `-trimpath -buildvcs=false -mod=readonly` and
  `GOTOOLCHAIN=local`; two builds of one commit from different paths and
  module caches came out byte-identical. `deploy/verify-release.sh` rebuilds a
  published release and compares every digest.
- SECURITY.md now says what you still have to trust: the release key, the first
  install, bastion updates, agent updates (which happen without an approval),
  the agent itself, and the platform.
- Upgrading from 0.40.0 or earlier needs nothing: those versions do not check
  signatures and update to this one as before. From this version on, an
  unsigned manifest is refused.

## 0.40.0 (not published)

*Later releases were merged before this was published; 0.42.0 carries these changes.*

- **Approvals from the taskbar.** On the machine that is your approval device,
  an ask from one of your hosts now raises a Windows notification. Clicking it,
  or the new first line of the tray menu ("N approvals waiting — open…"), opens
  an approvals window with no menu in between: a small app window where Edge is
  installed, otherwise a browser tab. It lists every ask in the device's own
  words with Approve and Deny, and "Approve all shown" when there are several.
  Before this the only way to read or answer an ask was `device-approvals` and
  `device-approve` at a console.
- Approve signs exactly as `device-approve` does: this device's key, the
  purpose the device derived when the ask was filed, one run, an hour at most.
  "Approve all shown" keeps the console's rule: it signs only the asks the
  window drew and leaves any that arrived since pending, named. Deny is final
  for a day, as on the console.
- The window does not redraw itself while you read it. A line at the top checks
  every few seconds and, when an ask arrives or is answered elsewhere, says so
  with a "Show them" button; the list, and what "approve all" would sign, change
  only when you act. An ask answered at the console while "approve all" runs
  is skipped and the rest are still signed.
- The same window lists the requests waiting for a code on this machine
  itself, and answering one there keeps you in the window. The front page says
  when asks are waiting and links to it.
- A sign-in link may now land on the approvals page directly. It can land on no
  other page it names; anything else lands on the front page.

## 0.39.2

- No code change: the same code as 0.39.1 under a new version. 0.39.1 was
  held back from automatic updates after one machine that had taken it went
  silent. That machine had run 0.39.1 cleanly for over four hours, and it lost
  all of its network traffic, not only the bastion's, and came back with no
  change while still on 0.39.1. A held version is never released again, only
  superseded, so updates can move again from this version. On a machine that
  needs an approval for a self-update, 0.39.2 must be approved again; an
  approval given for 0.39.1 does not carry over.

## 0.39.1 (held)

*Superseded by 0.39.2, the same code under a new version.*

- The op sandbox shows the op's own directory at `/opt/bastion-op`, a new
  name for the same mount point. Nothing on the host side names that path.
- Comments and tests no longer name internal documents, people or platform
  source paths, so the published tree reads on its own.

## 0.39.0

- **A terminal no longer needs the host's signed management grant.** A shell
  is the person's own act in their Terminal app (rung 8), and the authority
  for it is what this machine checks: a root shell is approved here with the
  code; `session:open` on a machine anchored to a host takes the person's
  approval from their device or this console, bound to that one session; on a local machine the pairing's caps are the
  authorization, as for every other write on a person's own machine. A grant
  that is presented is still verified (a deny in it still refuses), and the
  key the session frame offers is still pinned by the same rules. With this
  the host's standing `session:open` / `session:root` grant can be revoked
  once the fleet runs this version.

## 0.38.0

- **Mirroring into a slot server, done by this machine.** A slot server has no
  network, so it cannot pull the repos the person asked it to mirror. A reach
  grant may now carry `mirrors` — each an https upstream and the server repo it
  lands in — as part of what the person approves (its purpose binds the list;
  a grant without mirrors keeps the 0.36.0 purpose byte for byte). The new
  `service` verb `mirror` runs an ordinary `git fetch` of each approved source
  over this machine's OWN connection — the code never touches the platform —
  and pushes it into the server through its pinned socket.
- The fetch is held to the public internet on every machine: each source's host
  must resolve only to public addresses, and git is pinned to the vetted one
  (http.curloptResolve) so a second lookup cannot answer with a local one.
  https only, no redirects, no credential helpers, no user or system git config.
  A git older than 2.37 is refused, because it ignores the pin without an error.
  Addresses counted as internal now also include 0.0.0.0/8, 198.18.0.0/15 and
  240.0.0.0/4. Addresses in the well-known NAT64 prefix and in 6to4 are judged
  by the IPv4 address inside them, so an IPv6-only network with DNS64 still
  reaches public sites; the rest of 64:ff9b::/32 (local-use translators) is
  refused.
- A mirror source is checked against one allowlist pattern, the same on the
  host: a named host whose last label starts with a letter, digits for a port,
  and a path of plain characters and two-digit escapes. An IP address or a
  numeric host is refused, because curl reads "127.1" or "0x7f000001" as an
  address before it looks at the pin. Entries are visible ASCII only, and no two sources may
  land in the same repo, since a sync prunes and would erase the other
  source's branches. Both sides run the same test vectors.
- The push goes through a loopback bridge opened for that one push. It answers
  only a random path given to the git child, and it dials the server's pinned,
  uid-checked socket. The path is visible in the git child's command line while
  the push runs, which reaches only the server's anonymous pages. The host's credential for its own server rides in the environment,
  never on the command line.
- A sync is standing work under the approved list: no per-run approval, but
  only for the host the grant names, and not while its writes are quarantined.
- The mirror cache is the bastion's, outside the directory the server owns.
- Tests stub git and DNS; an opt-in end-to-end test (BASTION_MIRROR_E2E=1)
  mirrored two public GitHub repos into a no-network Gitea for real.

## 0.37.0

- **Ops: a program the host wrote runs here only under signed terms, in a
  sandbox first.** An op is a directory (`op.yaml` + `run`) the host built and
  tested; its identity is the sha256 of the directory's canonical form. It
  reaches this machine only with terms signed by the host's key and verified
  under the pinned one (`op_sync`): the bundle must hash to the sha256 the
  terms name, and the manifest must parse — a fixed interpreter (`/bin/sh`,
  `python3`), typed params, absolute file effects that are never `/`, a time
  limit under ten minutes, `dry_run` / `apply` / `verify` modes, and `undo`
  stated. Two terms: `op_run` (once — these params, ≤ 24 h, one use) and
  `op_grant` (from now on — param bounds, ≤ 30 days, a use count, `user` only;
  root is never reusable), held in `ops.json`; both carry the person's approval
  from the device or the console, and a device signs them because their purpose
  names the machine.
- **The executor (Linux, the root daemon).** `op_dry_run` runs the op in a
  throwaway sandbox — the bastion re-exec'd in fresh namespaces; an overlay
  over this machine's root filesystem and one over each of its other mounted
  disks (ext4, xfs, btrfs, f2fs, zfs, jfs; a network share or a vfat partition
  is not carried, and an effect on one refuses the run by name), all on a
  256 MiB tmpfs; no network; a fresh `/proc` with `/proc/sys` and the other
  machine-wide knobs read-only; `/sys` `/dev` `/run` `/tmp` `/var/tmp` masked;
  the op mounted read-only; rlimits; every capability that reaches past the
  filesystem (modules, clock, raw I/O, device nodes, mounts, reboot) dropped
  and no new privileges; the person's session user for `privilege: user`;
  killed at `time_limit` — and reads what it changed off the upper layers:
  created / changed (with a line diff) / removed. Anything else — a symlink, a
  hardlink, a replaced directory, a special file — or any change outside the
  op's declared effects refuses the run, and the refusal counts as a strike
  (a box that cannot sandbox at all is its own state, never the host's
  strike). This machine's own record — the config dir with its identity and
  pinned keys, pairings, ops.json and nonce ledger, and any pairing's DCN
  dir, as spelled and as it resolves, plus `/etc/privatae-bastion`,
  `/var/lib/privatae/freeagent` and `/var/lib/privatae/bastion` — is masked
  inside the sandbox with an empty read-only tmpfs (an op cannot read,
  write or remove it), and no effect or change may sit at, under or above
  it, whatever the manifest says — a glob is judged segment by segment
  against each of those places, and matched the same way against a change
  (equal segment counts, so no class or escape ever spans a `/`; a
  backslash is refused outright): `/etc/*.conf` is an effect,
  `/etc/privatae-*` or `/etc/*/observe.kubeconfig` is not; a record that
  cannot be enumerated refuses every op. A removed
  folder is named on the card with what it held and lands as that; one that
  holds a mount the sandbox did not carry is refused. **Apply is a committed dry run**: the same run again, checked again,
  and bound to the change list the dry run showed — the report names that
  list by sha256, the apply's terms and the person's approval carry it, and a
  run that would change anything else lands nothing — then the upper landed
  file by file, then `verify` in a fresh sandbox. Rung 6
  allows file effects only; Windows and macOS refuse every op and the beat says
  `sandbox: false` with the reason. `op_grant_run` runs under a held grant,
  params checked against the schema and the bounds, a use spent per apply.
  Every run writes an audit line and a record under `ops/runs/`; a host
  that lost an apply's answer reads what became of it with `op_run_status
  <nonce>` (a read: found / applied / the error / the change list; the
  box burns a run's nonce BEFORE the op runs, so "applied already" on a
  re-send means attempted, not landed). Console:
  `privatae-bastion ops` lists what is held; `ops drop <grant>` takes a
  standing grant back. The `ops` capability family joins the ceiling and the
  console page.

## 0.36.0

- **Reach grants for the service slot.** Holding the `services` family no
  longer lets a host reach every server on this machine. The forward now also
  requires, on every connection, a verified REACH GRANT naming that host and
  that server (service_reach.go) — default-deny. A reach grant is signed by the
  host with the entity key pinned here, approved by the person (on an anchored
  machine the box verifies and spends that approval, so a revoke is final), and
  installed with `service_grant_sync`; `service_grant_drop` and the heartbeat
  reconcile (`service_grants`, two missed replies) take it away. A host can
  install reach only for itself: the grant's subject must be the pairing that
  sends it. It lives beside the store grants in the pairing's grants.json.
- **A signed record's kind is checked.** The store-grant verifier parsed `kind`
  and never compared it, so any record the entity key signed could be offered
  as a store grant. It now requires `dcn_store_grant` (every store grant has
  carried it since store grants existed); a move plan is checked as a move plan
  through a shared signature-and-expiry check; a reach grant as a reach grant;
  and a terminal is opened only by a management grant — a signed record that
  declares ANY kind is refused there.
- The approval device files reach-grant asks (their purpose names the machine),
  so a machine that approves only through a pinned device can approve them.
- Stopping a server drops every reach grant for it, for every host, so the next
  server built under that name inherits no one's reach.
- The enforcing report lists the reach grants held and names the pairing's own
  host name (`pairing_host`) — the subject a reach grant must carry — and the
  given page says a server needs a reach grant per host.

## 0.35.0

- A server in the service slot has NO network. It runs with `--network none`
  and serves on a unix socket in its own data directory; the host's tunnel
  forward is spliced to that socket and is the only way in. Measured before
  choosing it: the default bridge reached the internet, the machine's LAN
  address and its own services; an `--internal` network still reached the
  machine's own services through its gateway; `--network none` reached
  nothing. "AI on your network, not your machines": a server a host built here
  cannot reach this machine, your network or the internet.
- `up` names the server's socket file (`socket`) instead of a port, and the
  approval binds it. Only a server that can listen on a unix socket can run in
  a slot (Gitea and Forgejo can: PROTOCOL=http+unix).
- The forward serves a slot only while its container reports network mode
  `none`, checked on every connection.
- The forward connects only to the server itself. The container owns its data
  directory, so the socket's name must be a socket (a symlink or a plain file
  there is refused, never followed), and after connecting the kernel's record
  of who is listening (SO_PEERCRED / LOCAL_PEERCRED) must be the server's own
  uid. `data_uid` is therefore required and non-root. Without this, a server
  could swap its socket for a link to a root-owned one — the container
  runtime's, say — and the host's tunnel would reach that instead.
- The forward dials the exact socket it checked. The name is opened with
  O_PATH|O_NOFOLLOW (a link fails to open), the open file is confirmed to be a
  socket, and the connection goes through /proc/self/fd/N, which the kernel
  resolves to that inode whatever the name points at by then. A server that
  renames a link to a same-uid host socket into place between check and dial
  reaches nothing: measured over 400 racing dials, 0 reached the decoy (dialling
  by name reached it 165 times). Linux only; elsewhere the slot is refused and
  never advertised.
- The given page says the server has no network.

## 0.34.0

- A host can run a server on this machine that stays up: the service slot.
  A new harness mode, `service`, has three verbs. `up` pulls the image the host
  names and starts it with a restart policy, no new privileges, every
  capability dropped, and one mount: the slot's own data directory under the
  bastion's config dir. `down` removes the container and keeps the data unless
  the request says `purge`. `status` reports each slot.
- Each slot gets a stable tunnel port in 18100-18199. The host dials this
  machine's tunnel address on that port and is spliced to the container on its
  bridge IP. Nothing is published on the machine's own network.
- It is its own capability family, `services`, separate from `harness`: a
  grant to run jobs here is not a grant to leave a server running. The family
  is checked on every accepted connection and on every verb. On an anchored
  machine a member host cannot replace or stop a server another host built.
- The heartbeat advertises `services` and lists the slots with their ports, only
  to a pairing that holds the family on a machine with a container runtime.
- The "what this machine gives away" page describes the new family and counts
  families from the list instead of a fixed seven.

## 0.33.0

- **A write on an anchored machine runs only on the person's approval, verified
  and SPENT here.** Every management op is a read or a write (`writes.go`):
  reads — `observe:*`, `computer:*`, `uptime`, `audit_fetch`, the dcn reads,
  `ctx_get`, `model:list`, `pairing_list`, the stepup and device asks — still
  answer on the anchor host's word; every write (`ctx_put/del/extract`,
  `backup_fetch`, `model:drop`, `session:open`, `harness:run`, the box-wide
  directives `self-update`, `contain` — by pid and by finding — and mirror
  placement, and anything unclassified) needs a live approval bound to this
  op, this machine and a digest of exactly its arguments, single-use, spent the
  moment it is accepted and before the act runs. Ops that already carried an
  approval (`dcn_grant_sync`, `dcn_plan_apply`, `model:pull`, `session:root`)
  keep theirs; a revoke (`dcn_grant_drop`, `pairing_grant_drop`) is never held
  back. `egress` and `inference` USE the machine and change nothing on it — they
  run under the user's egress rules and the inference cap as before — and on an
  anchored machine the store-mutating half of the ollama forward (`/api/pull`,
  `/api/delete`, `/api/create`, …) is refused for every pairing, the anchor
  included: models change through `model:pull` / `model:drop`, which spend an
  approval. Before this the anchor pairing passed the whole ceiling, and on a
  fleet anchored to one host that host's word was the only check on every
  write. A local (unanchored) machine is unchanged: the pairing is the
  authorization on a person's own computer. "Unenrolled passes" is gone for
  anchored machines — no factor and no device means every write is refused,
  and the refusal names both ways to fix it.
- **The approval device.** `privatae-bastion device-init` makes the person's
  own machine the device; `sudo -H privatae-bastion pin-device <key>` on each
  governed machine accepts approvals it signs. The pod files an ask on the
  device from the plain DETAILS of what the machine is being asked
  (`device_request <details_b64> <server>`); the device derives the purpose it
  will sign and the words it shows from those same details — a pod cannot show
  one sentence and have another signed — and the person reads them
  (`device-approvals`) and taps (`device-approve <id>|all` / `device-deny`).
  The governed machine verifies the signature under the pinned key, derives the
  purpose itself, refuses an expired, over-long, multi-use, replayed or
  wrong-purpose approval, and burns the nonce. The device lane answers only the
  person's own host. **Root is never approved from a device**: `session:root`
  still takes the code at the machine, on top of anything else. The console
  with a factor enrolled is the other way to approve a write, through the
  existing `stepup_request` flow with a new `mgmt_op` kind.
- **A repeated directive runs on the approval already given.** The host resends
  `self-update` and `contain` on every beat until it reads the result, and a
  mirror placement for as long as it stands; the machine remembers the act it
  approved (`directive_approvals.json`: ten minutes for a swap or a kill, until
  disabled for a mirror) so the person taps once per act, not once per beat.
- **The anchor's key is never taken from a first offer on the DCN or session
  lane on an anchored machine.** It is pinned from the anchor's own first
  `pairing_grant_sync` (as before) and every later offer is checked against it.
  A member host's key still pins on its first use until the anchor-signed
  pairing grant carries `verify_key` (the field is read as soon as a host
  fills it).
- **No open-ended terms.** A DCN store grant or a session grant with no expiry
  no longer verifies. The host has always signed one; pairing grants stay
  open-ended this release.
- **The person at the machine always wins.** The local switch covers the
  box-wide directives under a new family `directives` (a card on the console
  page); `approvals drop <id>` takes back an unused approval; `grants drop
  <store>` removes a held folder grant; `quarantine clear <host>` lifts a hold.
  `--host` is taken anywhere on those commands.
- **The lane watches itself.** Every refusal on the management lane goes on a
  ring the enforcing report carries (`refusals`, newest twenty); five refused
  writes from one pairing inside ten minutes — refusals the host could have
  known better than to send, never a read, an op this build does not know, or
  "this machine holds no way to approve" — close that pairing's write lanes
  here for ten minutes, doubling on repeat (fail2ban's defaults), forgiven after
  a clean day; reads and revokes untouched; reported as `quarantine` /
  `quarantined`. The report also says `write_gate`, `device`, `second_factor`,
  the `device_keys` a machine accepts and, on a device, `approval_device` and
  `approval_device_key`, so the host can find the device and tell a machine
  whose writes are all refused from one that is merely quiet. Audit lines carry
  `args_sha256` and the approval each gated write spent.
- **The egress lane reaches the public internet and nothing else on an anchored
  machine.** Loopback, link-local and private destinations — this machine's own
  services, its LAN, the mesh — are refused before any dial, whether named by
  address or by a name that resolves to one; that is what lets egress stay a
  USE of the machine rather than a write. The harness approval binds the whole
  run (id, mode, image, repo NAME, branch, prompt, command, worktree digest,
  port, minute cap, lab fields), and the clone URL must name the approved
  repository. The device signs only asks whose purpose names the machine
  (`mgmt_op`, `dcn_store_grant`); a move plan or a model pull is approved at
  the machine's console. The card shows every argument whole (a long one by
  its length and digest) and never the pod's free text. `device-approve all`
  signs only the asks the last `device-approvals` printed. A remembered
  `contain` is keyed on the agent's signature too, so a reused pid is a new
  act. A refusal on the harness lane counts toward the quarantine and a
  quarantined pairing spends nothing there.
- On an anchored machine the egress lane dials the ADDRESS the check vetted,
  never the name again (a name resolved twice is a rebinding hole). The
  harness approval names the repository as `forge-host/owner/name`, so a URL
  on another server does not pass as the same repository. The console and
  device cards blank C1 controls too, and the folder-grant card names the
  machine and drops the pod's free text.
- **Standing work under a store the person configured at the machine takes no
  tap:** `backup_fetch` (the nightly ship into the backup root set here) and
  `ctx_put` / `ctx_del` (the Host's context store, sandboxed to the context
  root set here) run as before: deterministic standing work takes no
  approval. `ctx_extract` executes an extractor and is approved per run.
  A git harness run must name a forge repository (never blank, never a local
  path or file: URL) and the clone takes `--` before the URL. The device and
  the console hand an approval to the pod ONCE — a re-filed ask after that is
  a new act, and a spent or expired approval is never handed back to be
  refused; a re-file that finds the tap the pod missed is answered approved.
- `backup_fetch` dials the address it vetted: the dialer's Control hook
  refuses a non-public address at the connection itself, so a name that
  answers public to the check and private to the dial gets nowhere. A
  refused ask wins over a delivered one for the same purpose on the device
  and the console, whatever order the store is read in.
- `backup_fetch`, `ctx_put` and `ctx_del` are
  standing work under a root set at the machine — no tap. The standing
  context lane cannot touch this box's own record: `sessions/` (the shell
  transcripts) is refused as a path for both. The `ctx_extract` approval binds
  the tool, the mime and the host's name for the document (`doc`, "ctx:<id>"),
  never the bytes or the single-use pull ticket, so one tap covers a re-ask.
- The transcript wall on the context lane is judged on the CLEANED path
  (`./sessions/x`, `a/../sessions/x` land there too), case-insensitively.
  The inline `ctx_extract` approval also binds the sha256 of the document's
  bytes, so a label cannot be approved for one document and used for
  another. The backup fetch never goes through an environment proxy.
- The heartbeat directives take their approval beside the directive
  (`"approvals": {"self-update": …, "contain:<pid>": …, "contain_finding:<id>":
  …, "mirror": …}`); this roll is the last host-directed self-update that runs
  on the anchor's word alone.

## 0.32.2

- A containment no longer leaves the processes above the agent hung. The
  kill-tree freezes the agent before killing it (0.32.0); sudo and su stop
  themselves when the child they wait on is stopped, and under a terminal the
  stop is relayed a hop further (sudo's monitor to sudo to the terminal
  wrapper). None of them was ever continued, so the killed agent stayed a
  zombie under a parent stuck in `T` until someone sent it SIGCONT by hand.
  The agent's ancestors are now read before the first freeze and, after the
  kill, every one that was running then and is stopped now under the same
  identity is resumed; they ride in the frozen-set journal too, so a bastion
  that dies between the freeze and the thaw continues them on its next start.
  One that was already stopped, or whose pid has changed hands, is left alone.
  Linux only for now: on macOS a process's stopped state cannot yet be read,
  so no ancestor is recorded there and the 0.32.0 behaviour remains.

## 0.32.1

- Comments only: containfinding and the kill-tree test state their rules without internal references.

## 0.32.0

- A host can stop a program the delta reports, not only one the agent plane
  recognises. The heartbeat's new `contain_findings` directive names findings
  by the host's order id and the finding's FINGERPRINT, never by pid; the box
  resolves the fingerprint to what is running under it now, from a fresh
  comparison against an accounting whose digest still verifies, and stops it
  only if it is a process reported `proc_new` or `proc_changed` whose
  fingerprint the accounting does not hold. Apps, anything the bastion
  started, init and the bastion itself are refused. Every order is answered on
  the beat under `contain_results` (`killed`, `not_a_finding`, `in_baseline`,
  `refused_app`, `refused_ours`, `no_authority`, `no_accounting`,
  `walk_failed`, `refused_anchor`, `kill_failed`), per pairing, carried out
  once per order id. Anchor-only, like every kill on this box.
- The guards hold across the WHOLE tree, not only the named process. An
  accounting entry, an app the user is running, anything the bastion started,
  and init are spared together with everything beneath them, and the rest of
  the tree is stopped (killing a parent does not kill its children, so a
  spared subtree survives re-parented). A finding that is the bastion's own
  launch context (an ancestor of it) is refused by name. Only what the box
  itself reports is containable: a `proc_new` at the new tier (never a
  package-managed binary) or a real `proc_changed` (never an unreadable
  digest), through the same noise filter the delta pass uses.
- A pid is not a process: each one's start time is read before it is frozen,
  after, and before the kill, so a recycled number is never killed and a
  stranger stopped by mistake is resumed at once. A process somebody else had
  already stopped is never resumed by us. What is frozen is journalled before
  the kill and thawed at the next start if the bastion died mid-kill; finding
  results are kept on disk, so an order answered before a restart is not run
  twice.
- Contain takes the whole tree with the tree FROZEN first. On unix every
  process in it is stopped with SIGSTOP, the tree is walked again until it
  stops growing, and only then is anything killed, so a child forked during
  the kill no longer survives it. A frozen process that cannot be killed is
  resumed. Windows, which has no SIGSTOP, kills as it walks and re-walks.

## 0.31.3

- The local agent runs on machines without openssl, Windows included. The
  bastion signs the agent's manifest with the key it minted, in Go (the agent
  prints `payload`, the bastion signs it, the agent records it with
  `sign --value`), and the agent's gate verifies in its own standard library.
  The `missing-openssl` state is gone: before this, every Windows agent
  stopped there and its context store was never indexed. Needs bastion agent
  0.1.11 or later: an older agent (a cached copy while the release manifest
  is unreachable) is refused by name rather than failing on an unknown flag.
- Agent 0.1.11 also reads PDFs itself (browser-printed ones included) and
  reads Office files on a memory and time budget.

## 0.31.1

- A process walk that did not happen is never an empty machine. Every
  platform's enumerator now returns an error when it could not walk
  (`/proc` unreadable, `ps` failing or empty, a refused Toolhelp snapshot,
  no enumerator at all), and every consumer says so in its own place: the
  heartbeat withholds `agents` and carries `walk_failed` in its detect
  summary; the accounting refuses to be taken; a delta pass compares
  nothing, keeps its gone-and-held clocks, and prints that nothing was
  compared; the machine store closes no finding on such a pass on any
  platform; the kill guard stops nothing; the sanction and policy pages
  banner the failure instead of drawing the tick; the policy census records
  it instead of a clean pass. A measured agent list travels with
  `agent_scan_ok: true`, so the host can tell an empty list it can vouch
  for from one it cannot. Found in review of a containment report (a containment
  the host read as carried out because the box sent an empty list for a
  failed walk).

## 0.31.0

- Three new read-only ops, `observe:alerts` / `observe:metrics` /
  `observe:logs`: the pull half of the observe family, reading an
  Alertmanager / Prometheus / Loki on the box's own network over HTTP. The
  admin names the endpoints once at install; the host sends only a name out
  of a fixed table, never a URL or a query. Alert counts also ride the
  heartbeat.

## 0.30.5

- Comments throughout the source rewritten as plain rationale.
- The installers no longer carry an in-place upgrade from the previous
  binary name. A machine still on that name reinstalls and pairs again.
- State directory, mirror container names and the unprivileged session
  account now use the `privatae-bastion` name only.
- Module path is the repository's own address.
- Async model pulls: the start reply was read without the lock while the
  download goroutine wrote to the same record (a data race in the daemon);
  the reply is now a snapshot taken under the lock, and every job signals
  its completion. Two intermittently failing tests fixed by the same change.
- The console clock seam is swapped atomically; a disk-map drop timer
  firing while a test pinned the clock was a data race.
- A machine marker naming a state directory that no longer exists is
  treated as absent, so a machine whose state moved can pair again.
- The other-bastion scan and the unprivileged session account look for the
  current name only; an install still under the previous name is not
  reported and its session account is not used.
- SECURITY.md, CONTRIBUTING.md and this changelog added.

## 0.30.4

- Licence changed to GNU GPL v3 or later.
- The installers verify the licence file users are pointed at.

## 0.30.1 to 0.30.3

- First releases published to the public repository: neutral names, no
  internal paths, and a release ratchet so the published source always
  corresponds to a built and verified artifact.

## 0.30.0

- Republish carrying four merged changes the published 0.29.0 predated.

## 0.29.0

- Share one model with another host: a model scope in the grant, and a
  redeem the anchor can direct.

## 0.28.0

- The context surface, complete: what it holds, what you asked, and who
  asked. The context page reachable from the tray.

## 0.25.0 to 0.27.0

- The local console: banners, the interrupt, what was given away, and setup.
- The disk map, sanctioning, and the dry-run policy.
- Windows: the bastion gets a home directory, `status` says whether it is
  running, and a second bastion is refused instead of dying on a port bind.
- A terminal session no longer requires a folder grant first.

## 0.24.0

- The model store: `model:list`, `model:pull`, `model:drop` under their own
  capability family, with approval on the machine.
- A networked box with no anchor serves nothing, on every lane.
- Windows: a self-update no longer ends as a silent shutdown.

## 0.22.0 and 0.23.0

- `claim-anchor` takes no token when the box already serves the host, and
  `--host` names which pairing on a shared machine.
- Windows can administer its own machine: the anchor gate works there.

## 0.21.0

- Machine marker and singleton guard: one bastion per machine.
- Second-bastion detection: the box looks at its own machine and reports
  another install to the anchor host.

## 0.20.0

- On an anchored machine, the inference forwards are their own capability
  family, and self-update, containment and mirror placement are directed
  only by the anchor host.
- The managed local agent runs as the granted folder's owner on root
  installs.
- Endpoint rotation never spends the live tunnel probing an unroutable
  endpoint.

## 0.19.0

- The bastion no longer serves an MCP ingress. Nothing on the machine drives
  the host.

## 0.18.0

- The user install stops deleting a running bastion.

## 0.17.0

- The session lane (an interactive terminal streamed to the host) honours
  the anchored machine's capability grants.

## 0.16.0

- Networked mode: a root-owned service on a shared machine, anchored to one
  host that approves every further pairing. Pairing grants.

## 0.15.0

- `observe:*` op family (sockets, firewall, units, disk, kernel, k8s, net)
  and posture carried on the heartbeat.

## 0.14.0

- Peer announcement between bastions and machine ownership (`claim-owner`).

## 0.13.13 and 0.13.14

- Relay candidate list, handshake-probed endpoint rotation, self failover,
  first-failure grace and a rotate backoff cap.

## 0.13.12

- Every observation carries an origin (interactive, remote, scheduler,
  service, agent) and a typed evidence list. The `automation` kind and the
  scheduler inventory. Every shell-out runs under a timeout.

## 0.13.10 and 0.13.11

- Computer observe: the machine map (`computer:inventory`,
  `computer:windows`) and one app's accessibility tree (`computer:tree`).

## 0.13.9

- GUI helper processes collapse into their app; containment refuses apps.

## 0.13.6 to 0.13.8

- Agent observe on Windows and macOS, local-model detection, the
  critical-action approval kind, and scanning the second factor from a QR
  code instead of retyping it.

## 0.13.5

- Second factor on the machine: `stepup-enroll`, `approvals`, `approve`,
  `deny`. Move plans (`dcn_plan_apply`).

## 0.13.2 to 0.13.4

- The managed local agent: installed and run from the signed grant, living
  under the store root, with a paged catalogue.

## 0.13.0

- Git lane: local git reaches the forge through the host.
- Local-agent lane: search and sanitised range reads over mTLS.
