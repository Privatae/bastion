# Your Host connects to a server

A Host on your own computer sits behind your home router. A server on the
internet can't open a connection to it, and nothing on your home network
should be opened for it. The server can be reached, though. So for a server
your Host can reach but that can't reach it back, your Host opens the
connections, to one port on the server, and the bastion there runs every lane
over them exactly as it runs them over a connection it opened itself.

Nothing changes but the direction of the TCP connection. Inside it the
bastion is still the TLS client, the Host's CA is still the only root it
trusts, the Host's certificate still names `host.cseries.internal`, and the
bastion still presents its operator certificate, which the Host signed at
pairing. The lanes, the bearer, the heartbeat and every op are the ones in
[lanes.md](lanes.md) and [host-on-this-machine.md](host-on-this-machine.md).

## For the person

On the server:

    privatae-bastion pair --open

It shows a code, good once and for 15 minutes, and the port (8812). On your
Host, choose "Add a server" and give it the server's address and the code.
That is all: the pairing finishes by itself, the server's terminal says so,
and from then on your Host connects to the server whenever it runs. If a Host
is already in charge of the server, the new one waits for it to admit it, as
any other Host does ([approvals.md](approvals.md)).

**Who is in charge.** Run with machine authority (root, or an Administrator
terminal) on a server no Host is in charge of, `pair --open` puts the Host
that pairs through it in charge of the server: it becomes the anchor
([anchor_local.go](../client-go/anchor_local.go)), and the Host counts the
server as the person's own. A local-mode bastion is made networked for it,
unless it already serves another Host the person said yes to. A Host on the
server itself still wins (paired, and not revoked), and an organisation's
policy that names another Host still decides. With a Host in charge, each
terminal and write on the server waits for the person's approval: enrol a
second factor there (`privatae-bastion stepup-enroll`).

**Adding it again.** The same Host pairing the same server again, through a
fresh `pair --open` code, replaces its pairing in place: no `unpair` first.
It is the same Host when its connection presents the CA the pairing already
pins, whatever handle it gives. The pairing gets new credentials and keeps its
state, its grants and, when it is in charge, the anchor (under a new name too,
its pinned key kept). Another Host with the same name is refused.

Right after `unpair`, the running bastion holds the port until it sees the
pairing gone (within 15 seconds); `pair --open` waits for it, up to 25
seconds, and says so.

**Firewall.** The server needs one port open inbound: **TCP 8812** (or the
one given with `--port`). Nothing on your Host's network needs opening, and
nobody has to touch the server's own firewall: while the port is in use (a
pairing whose Host connects here is active, or a pairing window is open), the
bastion keeps a rule of its own that allows it, and removes that rule when the
last such pairing and window are gone, and on `uninstall`. Every 5 minutes the
running bastion also puts its rule back if it went while the port is still in
use (removed by hand, or the firewall reset), unless a rule of the machine's
own now allows the port. Each add and remove is in the audit, and `status` and
`doctor` show the rule.

- Windows: an inbound rule named "Privatae bastion: your Host connects (TCP
  8812)", allowing TCP 8812 to the bastion's own program only, on every
  profile, made with `netsh` from System32.
- Linux with ufw on: `8812/tcp` allowed, with the comment "privatae-bastion:
  your Host connects". With firewalld running: the port added to the default
  zone, now and permanently. The bastion never turns either on or off or
  changes anything else in it, and a rule of the machine's own that already
  allows the port in from anywhere is left alone (and never removed). ufw
  tells the bastion's rule apart by its comment, so a ufw rule without it is
  never removed. firewalld keeps no comment: a port the bastion added and you
  later also add yourself reads as the bastion's, and goes when the door is no
  longer in use. Running as an account that can't change them, it says what
  to run.
- Rules of another kind (nftables or iptables of the machine's own) are not
  changed: `status` and `doctor` say once that TCP 8812 needs allowing there.
- macOS: with the application firewall on, the bastion's program is allowed
  (`socketfilterfw --add`, `--unblockapp`) and removed again after, by the
  path it was allowed for (a bastion that moved removes its old path's
  entry). `--listapps` is read entry by entry: only an entry for the
  program's exact path that allows incoming connections counts. macOS 15
  lists names without paths (`privatae-bastion (state: 1)`), so there the
  program's name is matched. An entry the person set to block, and "Block all
  incoming connections", are the person's settings: they are reported and
  never changed. This has not been run on a Mac yet.
- A cloud provider's firewall or security group is outside the machine: allow
  TCP 8812 there, from anywhere or from your home address.

## What the port answers

The port is open only while the bastion serves a pairing of this kind, or a
pairing window is open on it. Before the Host has proved itself it answers the
TLS handshake and nothing else, and it never forwards a byte anywhere: a
connection it keeps is a lane of a pairing it already serves.

- A connection whose certificate does not verify under the pinned CA of
  exactly one pairing served there, for `host.cseries.internal`, is closed at
  the handshake. So is one that names no protocol, or the pairing protocol
  with no window open.
- At most 256 handshakes run at once, 8 from one address (an IPv6 address
  counts as its /64), each with 10 seconds to finish. 64 of them are kept for
  addresses a Host proved itself from in the last 7 days (its certificate
  verified for a pairing this bastion serves, on this port or another, or it
  paired through the window), so
  that a flood from any number of addresses never holds them and your Host
  gets in at its first try. Every other address is admitted only while fewer
  than 192 are running, and, as OpenSSH's `MaxStartups` does, once 64 are
  running it is refused at random, with a chance of 30% rising evenly to
  certain at 192: a new Host pairing on a quiet port always gets in, and a
  flood fills slowly. Those addresses are kept in memory only, at most 64 of
  them, never written anywhere: a bastion that has just restarted knows none,
  and a Host connecting from an address it has not connected from before
  (a new home address) is admitted as any other until its first connection
  succeeds.
- A wrong pairing code costs a wait of 1, 2, 4 and 8 seconds before the next
  try, during which the window is not offered at all; the fifth closes the
  window.
- The audit (`pairing_audit.jsonl`, and the system log, [audit.md](audit.md))
  records the window opening and closing, each wrong code, each pairing made
  or refused through it, each time a Host connects after having no connection
  and each time its last connection closes, and refused connections (once per
  address per 10 minutes, and at most 256 addresses per 10 minutes, so a scan
  does not fill it).
- A connection offered the window during its handshake starts nothing if,
  by the time the exchange begins, the window was closed at the terminal,
  expired, closed by the fifth wrong code, or is inside a wrong code's wait;
  and the Host is not asked to sign, nor the pairing saved, once the window
  is closed.

## Wire contract (what the Host implements)

Version 1. All JSON is UTF-8, one object per body.

### Connections and roles

The Host opens a TCP connection to the server's address and port, and is the
**TLS server** on it; the bastion is the **TLS client**. TLS 1.3 only. The
bastion sends the server name `host.cseries.internal` and offers, by ALPN:

| ALPN | Offered | The Host chooses it to |
|---|---|---|
| `privatae-lane/1` | by a bastion serving pairings | carry a lane of an existing pairing |
| `privatae-pair/1` | only while a pairing window is open | pair through the window |

The Host chooses exactly one of them; a connection that negotiates neither is
closed by the bastion.

### Pairing (`privatae-pair/1`)

The person gives the Host the server's `host:port` and the code. The Host
normalises the code: upper case, dashes and spaces removed, `O` read as `0`,
`I` and `L` as `1`. It is then 20 characters of
`0123456789ABCDEFGHJKMNPQRSTVWXYZ` (100 bits). That string, as bytes, is the
HMAC key below; the code itself never crosses the wire.

TLS: the Host presents its certificate for `host.cseries.internal` **followed
by its CA certificate** in the chain (the bastion takes the CA from there and
pins it). It does not request a client certificate.

Then, over that one connection, kept open (HTTP/1.1 keep-alive), the bastion
sends three requests and the Host answers each. Host header
`host.cseries.internal`. Let

- `leaf` = SHA-256 of the DER of the Host's certificate as presented on this connection,
- `ca` = SHA-256 of the DER of its CA certificate,
- `proof(role)` = lowercase hex of HMAC-SHA256(key = code, message =
  `"privatae-pair-v1 " + role + "\x00" + leaf + ca + nonce_b + nonce_h`), the
  hashes and nonces as raw bytes.

1. `POST /v1/pair/hello` `{"v":1,"nonce":"<64 hex: nonce_b>"}` → 200
   `{"v":1,"host_handle":"home","host_name":"home.cseries.localhost","nonce":"<64 hex: nonce_h, fresh random>","proof":"<proof(\"host\")>"}`.
   The Host proves first, so a stranger who connects to an open window learns
   nothing to test codes against. A wrong proof counts as a wrong code.
2. `POST /v1/pair/redeem`
   `{"v":1,"proof":"<proof(\"bastion\")>","wg_public_key":"…","operator_csr":"<PEM>","hostname":"<server's hostname>","platform":"linux|windows|darwin","handle":"home"}`.
   The Host checks the proof (constant time) **before signing anything**; a
   wrong one is 403 `{"error":"…"}` and the Host should close the attempt. It
   then answers 200 with the redeem answer of a TCP pairing, with a transport
   of its own and no lane address:
   `{"operator_cert":"<PEM, the CSR signed by its CA for client auth>","ca_cert":"<PEM>","bearer":"…","transport":"host_dials","host_handle":"home","host_name":"home.cseries.localhost"}`.
   `ca_cert` must be the CA it presented; the CSR carries the device
   fingerprint as URI SANs exactly as at a TCP redeem.
3. `POST /v1/pair/done`
   `{"v":1,"state":"active|pending","host_name":"…","admitted_by":"<the Host in charge, when pending>"}`,
   or `{"v":1,"state":"refused","error":"<why, in words for the person>"}` →
   200 `{}`. The Host shows the person what it says. On `refused` it drops the
   credentials it issued; on `pending` it says who admits it and connects
   anyway (the server refuses its lane connections until it is admitted).

Both proofs bind the Host's certificate on this connection: a proof made on
one connection is worth nothing relayed onto another, and a machine the Host
was misdirected to can't pass step 2 without the code, so it never gets a
signed operator certificate. The bastion closes the connection after step 3.

### Lanes (`privatae-lane/1`)

TLS: the Host presents its lane certificate for `host.cseries.internal`
(signed by the CA pinned at pairing) and **requires and verifies** the
bastion's client certificate against its CA, as its lane port does. Then the
Host serves its lane routes on the connection, exactly as on its lane port:
HTTP/1.1, `Host: <the pairing's host name>:8443`, the WebSocket lanes
(`/bastion-harness`, `/bastion-mgmt`, `/bastion-egress`, `/bastion-serve`,
`/bastion-git`) and `/api/network/bastions/…`, every request with the bearer.

The Host sends nothing on a connection until the bastion has spoken on it (a
byte from the Host on an idle connection closes it), and each connection
carries one lane, or a run of requests, for as long as the bastion keeps it.

How many: the Host keeps **4 connections idle** (open, handshake done, no
request yet) at all times, and opens another each time one carries its first
request or closes, up to **64 open** to one server. The bastion holds at most
32 idle per pairing and closes any beyond that. A bastion with every lane
parked holds about 15 (2 harness, 4 session, 2 management, 4 egress and 2
serve workers, and the heartbeat), so a starting bastion draws a burst; a lane
waits up to 20 seconds for the next connection.

Keepalive and reconnect: TCP keepalive every 25 seconds on both sides (a home
router may forget an idle connection after 30). The server never connects to
the Host. When a connection fails to open or its handshake fails, the Host
tries again after 1 second, doubling to at most 30 seconds, with jitter, and
goes back to 1 second after a success. When the bastion restarts every
connection closes and the Host's redials bring the lanes back; when the Host
comes back after being away, the bastion beats at once.

### On the C-Series side

- "Add a server": the address and code fields, the three pairing requests on
  a connection it opens (an `ssl` server context on a connected socket:
  `asyncio`'s `loop.connect_accepted_socket(..., ssl=ctx)` or
  `ctx.wrap_socket(sock, server_side=True)`), and the pairing kept with the
  server's `host:port` and `transport: host_dials`.
- A dialler per such pairing that keeps the pool above, serving the existing
  lane app on each connection as if accepted on the lane port.
- Showing `done`'s words, and the server as connected or not from its
  heartbeat, as for every other bastion.
