# Security model

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
  [SECURITY.md](../SECURITY.md) for what that does and does not prove.
- **No secrets cached for git.** The credential helper fetches a token from
  the host on every auth and stores nothing itself, and `git-setup` resets
  the forge's helper chain before adding it. With git 2.46 or later, git's
  own store and cache helpers keep nothing, wherever they are configured; a
  helper that records everything it is given still receives the token. A git older than 2.46 gets the username
  and password, and for it only helpers configured before `git-setup`'s
  lines are kept out.

## How each claim is tested

[claims.md](claims.md) names, for each point above, the test that fails if
it stops being true, and says where there is none.

To report a security issue, please do not open a public issue. See
[SECURITY.md](../SECURITY.md).
