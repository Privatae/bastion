# A Host on this machine

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

## A Host in a VM on this machine

A Host with no platform that runs in a VM on this machine shares no kernel and
no directory with it. A C-Series Host
([Privatae/cseries](https://github.com/Privatae/cseries)) is one: it runs in
its own Linux virtual machine. Its installer, `npx cseries`, forwards three
ports of the VM (8800, 8810, 8811) to this machine's loopback, installs this
bastion as the machine's system service, and on every pairing runs these in
one elevated step (on Windows, from an Administrator PowerShell instead of
`sudo -H`):

```sh
# 1. The service's state, networked.
sudo -H privatae-bastion set-mode networked
# 2. Pair over the Host's enroll port, trusting its CA alone; the token is read
#    from standard input, never from the arguments.
sudo -H privatae-bastion pair --redeem-url https://127.0.0.1:8810/v1/local/redeem --host-ca host-ca.pem -
# 3. Anchor the machine to that Host: every write and terminal waits for your approval.
sudo -H privatae-bastion claim-anchor
# 4. Your authenticator, enrolled on that console and nowhere else.
sudo -H privatae-bastion stepup-enroll --console-only --host <the Host>
```

No Privatae account is needed. A plain `pair` and `run` as your own user also
pair with such a Host, but leave the machine local: not anchored, and with no
second factor until you enrol one.

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
refused before any container starts. Its model servers ride the serve lane,
below.

## The model servers on this machine

A pairing over the socket or the lane port reaches the model servers on this
machine over the serve lane, `/bastion-serve`, instead of the tunnel's
forwards. The bastion keeps two workers parked on the Host's lane; the Host
hands one a connection and names a service: `ollama`, `llm` or `pii`. The
bastion reaches the server set on this machine for it (`OLLAMA_ADDR`, else
`127.0.0.1:11434`; `PRIVATAE_LLM_ADDR`; `PRIVATAE_PII_ADDR`), and only when
every address it names is this machine, a container on a network made here
included. A server on another computer is refused, and so is an address sent
in place of a service; nothing is dialled for either. Each connection needs
the `inference` family and goes through the forwards' filter, so a model
scope, the `models` switch and an anchor apply as they do over the tunnel.
One pairing holds at most 16 streams, a stream silent both ways for 10 minutes
is closed, and each one is written to the pairing's audit log. Model
management for such a pairing (the model list, pulls and removals) reaches
`OLLAMA_ADDR` under the same rule, and when an address set here is not this
computer, the bastion prints a line in its output saying which one and what to
set. When the bastion runs as the machine's service, its output is its log:
`journalctl -u privatae-bastion` on Linux, `/var/log/privatae-bastion.log` on
macOS (readable by root only), and
`%SystemRoot%\System32\config\systemprofile\AppData\Roaming\privatae-bastion\bastion.log`
on Windows. When it runs in a terminal (`privatae-bastion run`), the line is
printed there.

The heartbeat lists what the lane serves in `lane_serves`, and advertises
`embed`, `llm-openai` and `pii` only for those. It never advertises the
service slots, or coder runs over TCP.
