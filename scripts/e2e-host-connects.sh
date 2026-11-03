#!/usr/bin/env bash
# End to end: a Host behind a home router's NAT connects to a server on the
# internet, which can't reach it back (docs/host-connects.md).
#
#   sudo scripts/e2e-host-connects.sh <workdir>
#
# Root, Linux, ip and nft. Everything runs in private PID, network and mount
# namespaces: no process, address, port or file of the machine it runs on is
# touched. ALL of /run and /tmp are empty mounts here, never a chosen
# subdirectory of them (a run that hid /run/privatae but not
# /run/privatae-bastion replaced a live bastion's ask.sock and context.sock),
# and so are the machine's bastion state, policy, machine marker and service
# units. The script refuses to go on if it can still see any of them. <workdir>
# must not be under /run or /tmp, which are hidden. Three namespaces:
#
#   server  203.0.113.1      the real privatae-bastion binary, `pair --open` then `run`
#   router  203.0.113.2 | 192.168.1.1   masquerades the home LAN; forwards nothing inbound
#   home    192.168.1.10     the stand-in Host (TestStandinHostProcess)
#
# Steps: the server can't reach the home Host; pair through the window with the
# code; lanes, heartbeat and a harness job over the Host-opened connections;
# the bastion restarts; the Host restarts; each again over the Host's
# connections. Exits 0 only if every step held.
set -euo pipefail
if [ -z "${E2E_INNER:-}" ]; then
	[ $# -eq 1 ] || { echo "usage: $0 <workdir>" >&2; exit 2; }
	exec env E2E_INNER=1 unshare --pid --net --mount --fork --mount-proc "$0" "$1"
fi
# E2E_INNER set by a caller skips the unshare above, and every mount below
# would then land on this machine's own /run: go on only as PID 1 of the
# namespaces that line makes.
[ "$$" = 1 ] || { echo "refusing to run: not PID 1 of a private PID namespace (E2E_INNER is set outside this script?)" >&2; exit 2; }
mkdir -p "$1"
W=$(realpath "$1")
SRC=$(cd "$(dirname "$0")/../client-go" && pwd)
log() { printf '%s e2e %s\n' "$(date -u +%H:%M:%S.%3NZ)" "$*"; }
fail() { log "FAIL: $*"; exit 1; }
case "$W/" in /run/* | /tmp/*) fail "the workdir $W is under /run or /tmp, which this run hides; give one elsewhere" ;; esac
case "$SRC/" in /run/* | /tmp/*) fail "the source $SRC is under /run or /tmp, which this run hides" ;; esac

# The Go caches stay where they are; HOME moves below.
export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOFLAGS=-mod=mod GOPROXY=off
case "$GOCACHE/" in /run/* | /tmp/*) fail "GOCACHE $GOCACHE is under /run or /tmp, which this run hides" ;; esac
# Hide this machine's bastion, whole: every runtime directory and socket (all
# of /run and /tmp), its service units, its machine marker and lock, its
# policy, and its state in root's home.
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /etc/systemd/system
mkdir -p /var/lib/privatae && mount -t tmpfs tmpfs /var/lib/privatae
if [ -d /etc/privatae-bastion ]; then mount -t tmpfs tmpfs /etc/privatae-bastion; fi
for d in ~root/.config/privatae-bastion ~root/.local/state/privatae-bastion; do
	if [ -d "$d" ]; then mount -t tmpfs tmpfs "$d"; fi
done
export TMPDIR=/tmp
mkdir -p /run/netns
# The guard: nothing of the machine's own bastion is visible from here.
for p in /run/privatae-bastion /run/privatae /run/systemd/private /run/dbus/system_bus_socket \
	/etc/systemd/system/privatae-bastion.service /var/lib/privatae/machine.json; do
	if [ -e "$p" ]; then fail "refusing to run: $p of this machine is still visible after hiding /run, /tmp and the bastion's state"; fi
done
for d in ~root/.config/privatae-bastion ~root/.local/state/privatae-bastion; do
	if [ -d "$d" ] && [ -n "$(ls -A "$d")" ]; then fail "refusing to run: this machine's bastion state $d is still visible"; fi
done
# The bastion keeps its door's own rule in a firewall it manages (doorfw.go):
# ufw's configuration is a private copy here, and the system bus, through
# which firewall-cmd reaches firewalld, is under the hidden /run, so neither
# is this machine's.
if [ -d /etc/ufw ]; then rm -rf "$W/etc-ufw" && cp -a /etc/ufw "$W/etc-ufw" && mount --bind "$W/etc-ufw" /etc/ufw; fi
export HOME="$W/server-home" XDG_CONFIG_HOME="$W/server-home/.config"
rm -rf "$HOME" "$W/standin" && mkdir -p "$XDG_CONFIG_HOME"

log "build: the bastion and the stand-in Host"
(cd "$SRC" && CGO_ENABLED=0 go build -o "$W/privatae-bastion" . && go test -c -o "$W/standin.test" .)

log "network: server 203.0.113.1, router NAT, home 192.168.1.10"
ip link set lo up
ip netns add router
ip netns add home
ip link add srv0 type veth peer name wan0 netns router
ip addr add 203.0.113.1/24 dev srv0 && ip link set srv0 up
ip -n router link set lo up
ip -n router addr add 203.0.113.2/24 dev wan0 && ip -n router link set wan0 up
ip -n router link add lan0 type veth peer name eth0 netns home
ip -n router addr add 192.168.1.1/24 dev lan0 && ip -n router link set lan0 up
ip -n home link set lo up
ip -n home addr add 192.168.1.10/24 dev eth0 && ip -n home link set eth0 up
ip -n home route add default via 192.168.1.1
ip netns exec router sysctl -qw net.ipv4.ip_forward=1
ip netns exec router nft -f - <<'NFT'
table ip nat {
	chain post {
		type nat hook postrouting priority 100;
		oifname "wan0" masquerade
	}
}
table ip filter {
	chain forward_home {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		iifname "lan0" oifname "wan0" accept
	}
}
NFT
# Even with a route to the home LAN, the server can't open a connection to it.
ip route add 192.168.1.0/24 via 203.0.113.2
ip netns exec home python3 -I -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",8811));s.listen();import time;time.sleep(3600)' &
sleep 0.5
if timeout 3 bash -c '</dev/tcp/192.168.1.10/8811' 2>/dev/null; then
	fail "the server reached the home Host's port: the NAT is not in the way"
fi
log "ok: the server cannot reach the home Host (192.168.1.10:8811 behind the NAT)"
B="$W/privatae-bastion"
# exec all the way down, so the pid a kill gets is the stand-in itself.
STANDIN() { exec ip netns exec home env STANDIN_STATE="$W/standin" STANDIN_SERVER=203.0.113.1:8812 "$@" \
	"$W/standin.test" -test.run '^TestStandinHostProcess$' -test.v -test.timeout 2h; }

log "pair: privatae-bastion pair --open on the server"
"$B" pair --open >"$W/open.out" 2>&1 &
OPEN=$!
for _ in $(seq 50); do grep -q 'code:' "$W/open.out" && break; sleep 0.1; done
CODE=$(sed -n 's/^  code: *//p' "$W/open.out")
[ -n "$CODE" ] || fail "pair --open showed no code: $(cat "$W/open.out")"
cat "$W/open.out"
(STANDIN STANDIN_MODE=pair STANDIN_CODE="$CODE") | grep standin || fail "the Host could not pair"
wait $OPEN || fail "pair --open: $(cat "$W/open.out")"
cat "$W/open.out" | sed -n '/Paired with/,$p'
grep -q '"host_dials": true' "$XDG_CONFIG_HOME/privatae-bastion/pairings/home.cseries.localhost.json" || fail "no host-dials pairing saved"
log "ok: paired through the window; the server dialled nothing"
# Opened here with machine authority on a machine nobody was in charge of:
# the Host that paired is in charge of it (the anchor).
grep -q '"anchor_host": "home.cseries.localhost"' "$XDG_CONFIG_HOME/privatae-bastion/anchor.json" || fail "the Host paired through the window is not in charge of the server"
grep -q 'is now the Host in charge of this machine' "$W/open.out" || fail "pair --open did not say who is in charge"
log "ok: the Host is in charge of the server (anchor.json)"

start_bastion() { "$B" run >>"$W/bastion.log" 2>&1 & BAST=$!; }
start_host() { (STANDIN STANDIN_MODE=serve) >>"$W/standin.log" 2>&1 & HOSTP=$!; }
beats() { grep -o 'beats=[0-9]*' "$W/standin.log" | tail -1 | cut -d= -f2; }
hellos() { grep -o 'worker-hellos=[0-9]*' "$W/standin.log" | tail -1 | cut -d= -f2; }
# A heartbeat goes once a minute, and at once when a run starts.
wait_beats_over() { local n=$1; for _ in $(seq 400); do [ "$(beats || echo 0)" -gt "$n" ] 2>/dev/null && return 0; sleep 0.2; done; return 1; }

log "serve: the bastion runs, the Host connects"
start_bastion
start_host
wait_beats_over 0 || fail "no heartbeat over the Host's connections"
for _ in $(seq 100); do grep -q 'HARNESS JOB' "$W/standin.log" && break; sleep 0.2; done
# The job reaches the bastion's harness over the Host's connections and its
# answer comes back. A Host in charge of a server has each job approved there,
# and this server has no second factor enrolled, so the answer is that refusal.
grep 'HARNESS JOB' "$W/standin.log" | grep -Eq 'exit=0|needs your approval' || fail "no harness job answered"
tail -3 "$W/standin.log"
ss -tn state established '( sport = :8812 )' | tail -n +2 | awk '{print "  server side of a Host-opened connection:", $3, "<-", $4}' | head -3
if ss -tn state established | grep -q '192.168.1.10'; then fail "a connection names the home address: the NAT was bypassed"; fi
log "ok: lanes, heartbeat and a harness job answered over connections the Host opened (they arrive from the router's 203.0.113.2)"

log "restart: the bastion stops and starts; the Host redials"
n=$(beats); kill "$BAST"; wait "$BAST" 2>/dev/null || true
sleep 1; start_bastion
wait_beats_over "$n" || fail "no heartbeat after the bastion restarted"
log "ok: heartbeat again after the bastion restarted (beats $n -> $(beats))"

log "restart: the Host stops and starts (same CA from its state)"
kill "$HOSTP"; wait "$HOSTP" 2>/dev/null || true
: >"$W/standin.log"
start_host
for _ in $(seq 150); do [ "$(hellos || echo 0)" -gt 0 ] 2>/dev/null && break; sleep 0.2; done
[ "$(hellos || echo 0)" -gt 0 ] 2>/dev/null || fail "no lane came back after the Host restarted"
log "ok: the lanes are back after the Host restarted ($(hellos) workers)"
wait_beats_over 0 || fail "no heartbeat after the Host restarted"
log "ok: heartbeat again after the Host restarted"

grep -E '"host_connected"|"host_disconnected"|"window_(opened|paired)"' "$XDG_CONFIG_HOME/privatae-bastion/pairing_audit.jsonl" | sed 's/^/  audit: /'
kill "$BAST" "$HOSTP" 2>/dev/null || true
log "PASS"
