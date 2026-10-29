# Tunnel and lanes

## Tunnel
A userspace WireGuard tunnel (gVisor netstack) scoped so this machine can reach
**only its own host**. No TUN device is created and `run` does not need root.
The tunnel is dialled from this machine. Its WireGuard UDP port, on every
address at a port the system picks when the tunnel comes up, drops every
packet that does not come from the host's key. Inside the tunnel, the
bastion accepts only on gated forwards: ollama (11434), an OpenAI-compatible server (18080) and a PII
sterilizer (18081) under the `inference` capability family, the last two only
when configured; one port per service-slot server (18100-18199); and one per
coder run (18200-18299). Nothing else listens.

## Git lane
A loopback HTTP proxy plus a `git-credential` helper, so your local `git` reaches
`git.privatae.ai` through your host. `privatae-bastion git-setup` prints the
three config lines: the proxy, a reset of the credential-helper chain for that URL
(so no other helper caches your token on this machine), and the helper itself.

## Worker lanes
Outbound-only reverse relays to the host: egress, management, harness, and
session. The management lane runs a **fixed-argv allowlist**. Ops that touch
your files are dedicated Go handlers with no shell. Two of them start a
program: text extraction invokes a local tool named in a fixed table
(`pdftotext`, `ffprobe`, and the like) from a fixed argv template, and the
caller supplies only the tool's name and the document; `dcn_grant_sync`
starts the local search agent's Python.

## Session lane
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
this machine, ends at the time you chose, at most 30 days after you gave it
(`--for 31d` is refused; grant again before it ends), and is written only by
that command with the code; nothing the host sends can create, widen or
extend it. A grant given before 0.55.0, when the longest term was a year,
ends 30 days after it was given. Each
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
