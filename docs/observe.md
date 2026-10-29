# Observe: what is running on this machine

Read-only, and reported so the host can show **why** rather than a verdict.

- **Agent observe.** Watches for AI-agent activity two ways and correlates by
  process: a process signal (known agent binaries, interpreter-wrapped ones by
  command line) and a network signal (connections to inference endpoints, both
  cloud APIs and local model servers). Each observation carries an **origin**
  (`interactive`, `remote`, `scheduler`, `service`, `agent`) and a typed
  evidence list with a confidence tier. Tools that drive the machine with no
  model of their own are inventoried as `automation` and promoted to `agent`
  only when model traffic joins them. Each also says who owns the account it
  runs as: `owner_class` (`domain_user`, `local_user`, `service`, `system`),
  `owner_admin` and `owner_interactive` (each `yes`, `no` or `unknown`; a
  group list or token that could not be read is `unknown`, never `no`).
- **Declared tool servers.** The files where Claude Desktop, Claude Code,
  Cursor, VS Code, Windsurf, Codex and Zed declare their MCP servers, per
  account and for the projects Claude Code lists, read and never written or
  connected to. Per server: client, scope, path, name, transport, whether it is
  a local process or a URL (and the URL's host), the launch command truncated
  like an agent's, the package and whether it is pinned, the **names** of the
  environment variables it gets, whether a value looked like a secret (the
  value is dropped where it is read), whether a remote server has
  authentication configured, and whether it is running, declared but not
  running, or running with no declaration. A command line keeps a URL's
  scheme and host only, and every flag, header or `NAME=value` that names a
  secret is replaced. A file is opened only once it is known to be a regular
  file (on Windows: a reparse point, directory or device at the path is
  refused, checked on the open handle), and in an account's home or project
  only when that account or root owns it (on Windows: the account whose
  profile it is, SYSTEM or the Administrators group; `files_foreign_owner`
  counts the rest). The files are read at most every ten minutes, and a read
  that does not finish holds the beats for at most 20 seconds in total
  (`timed_out` says it did not finish; until one read has finished, no server
  is reported).
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
- **Machine questions** (Linux: `observe:folders`, `observe:journal`,
  `observe:logins`, `observe:cert`). What a host would otherwise ask the
  person to run a command for, answered here. Each value is checked against
  its written rule before anything is read or run, and a refusal says which
  rule it broke.
  - `observe:folders <absolute path> [depth 1-3, default 2]`: the 25 largest
    folders under the path, down to the depth, and the total, on the path's
    own filesystem only, counted as `du -x` counts (disk blocks, a file with
    several links once). Only folders are named, never files. What could not
    be read, and filesystems mounted under the path, are listed against the
    folder that holds them, with a reason and a count. A relative path, one
    containing `..`, and `/proc`, `/sys` and `/dev` (or a link leading into
    them) are refused. The walk shares the 20-second op budget; one that runs
    out answers with what it measured, marked incomplete. It follows no link,
    and a folder swapped for one while it reads is listed as changed. While
    four earlier walks are still inside a read that has not returned, no new
    walk starts.
  - `observe:journal <unit> [minutes 1-60, default 15]`: one systemd unit's
    journal over the window, up to 5000 lines and 200 KB, newest kept. A name
    with no type is a service. The unit must be in systemd's unit-name
    alphabet and one this machine has, loaded or installed; otherwise it is
    refused, with the units whose names come close.
  - `observe:logins [hours 1-168, default 24]`: sshd's failed logins counted
    and ranked by source address and by user name (20 each), and the last 20
    accepted logins with user, source, method and time. A user name the other
    side sent is cut to 32 characters, and anything outside the characters
    account names use reads `?`. No raw line, key fingerprint or password is
    returned. Only lines sshd wrote as root are read (`_UID=0`), so another
    account cannot add login lines or bury the real ones.
  - `observe:cert <port> [server name]`: the certificate this machine's own
    TCP listener on the port serves: subject, names, issuer, dates, days left,
    and whether the chain verifies against this machine's roots for that name.
    The port must be one `ss` shows listening here.

  `observe:journal` and `observe:logins` first check that the bastion can read
  the system journal (root, as the networked install runs it, or a member of
  `systemd-journal`). An account that cannot is shown only its own lines by
  `journalctl`, which would read as a quiet machine, so they answer with the
  reason instead, and `observe:logins` reports its counts as -1.

The observe ops that send traffic are `observe:net`, `observe:k8s` (a
read-only query of a cluster API), the three monitoring ops above (private
addresses only, refused at the socket if a redirect or a DNS answer would move
the destination after validation) and `observe:cert`, which connects only to
this machine: loopback first, then an address of this machine the listener is
bound to. A build with no enumerator for its
platform **withholds** the capability, so the host can tell a machine that is
quiet apart from one that is blind.
