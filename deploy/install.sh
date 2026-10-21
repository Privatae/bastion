#!/bin/sh
# privatae-bastion installer (macOS / Linux). Run as root (a server), it installs the
# NETWORKED bastion as a system service (systemd on Linux, launchd on macOS), and the
# first host paired anchors it, so onboarding a server is two commands:
#   curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
#   sudo -H privatae-bastion pair <token>
# Run as your own user (a desktop), it installs the LOCAL bastion for that user.
#
set -e
# dl.privatae.ai, not privatae.ai/bastion: the download host is served from each
# edge's OWN local disk, so installs survive losing the platform datacentre, and
# DNS points it at the edge with the bandwidth for an install wave (~15MB a
# binary, and the primary sustains roughly 25x what the secondary does).
# Deliberately NOT env-overridable: the digest is checked against the manifest
# from this same base, so anything that can redirect the base can redirect both
# and the verification buys nothing. Hardcoded is the point.
base="https://dl.privatae.ai"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m); case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; esac

if [ "$(id -u)" = 0 ]; then bindir=/usr/local/bin; root=1; else bindir="${HOME}/.local/bin"; root=0; mkdir -p "$bindir"; fi
bin="$bindir/privatae-bastion"

# As root the default is the NETWORKED bastion: a root-owned service, anchored to
# the host it is first paired with, so every terminal and every write waits for the
# person's approval and every later host for the anchor's. A server left in local
# mode would serve its host with no approval at all. --local keeps a root install
# local (one host, the pairing's caps are the authorization); run as your own user
# it is always local. --networked is accepted and is the root default.
networked=0
local=0
for a in "$@"; do
  case "$a" in
    --networked) networked=1 ;;
    --local) local=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
if [ "$networked" = 1 ] && [ "$local" = 1 ]; then
  echo "ERROR: --networked and --local contradict each other; pass one" >&2; exit 2
fi
asked_networked=$networked

# paired_local DIR...: 0 when one of these state folders holds a pairing and
# its mode is not networked (no mode.json reads as local, mode.go boxMode).
# The service's own folder goes first.
paired_local() {
  for d in "$@"; do
    [ -d "$d" ] || continue
    if [ -f "$d/mode.json" ] && grep -q '"networked"' "$d/mode.json"; then return 1; fi
    [ -f "$d/config.json" ] && return 0
    for f in "$d"/pairings/*.json; do [ -f "$f" ] && return 0; done
  done
  return 1
}

if [ "$root" = 1 ] && [ "$local" != 1 ]; then
  case "$(uname -s)" in
    Linux) if command -v systemctl >/dev/null 2>&1; then networked=1; fi ;;
    Darwin) networked=1 ;;
  esac
fi
# A reinstall (an upgrade) of a machine already paired in local mode keeps
# local mode unless --networked is passed. Switched by default, its pairing
# would sit on an unanchored networked machine, which refuses every op until
# claim-anchor is run, and `pair` would accept a second host.
kept_local=0
if [ "$networked" = 1 ] && [ "$asked_networked" != 1 ]; then
  case "$(uname -s)" in
    Darwin) state_dirs="/var/root/Library/Application Support/privatae-bastion|${HOME}/Library/Application Support/privatae-bastion" ;;
    *) state_dirs="/root/.config/privatae-bastion|${XDG_CONFIG_HOME:-$HOME/.config}/privatae-bastion" ;;
  esac
  if paired_local "${state_dirs%%|*}" "${state_dirs#*|}"; then networked=0; kept_local=1; fi
fi
if [ "$networked" = 1 ] && [ "$root" != 1 ]; then
  echo "ERROR: --networked needs root — a networked bastion is a root-owned service (run with sudo)" >&2; exit 1
fi

key="$os-$arch"
tmp=$(mktemp); man=$(mktemp)
# Any exit before the final mv must leave nothing behind and install nothing:
# this script is piped to `sudo sh`, so a partial run is a root-privileged
# partial install.
trap 'rm -f "$tmp" "$man"' EXIT INT TERM

die() { echo "ERROR: $*" >&2; exit 1; }

# Pick the digest tool ONCE, here — not inside the command substitution that
# computes the hash. `exit` inside `$(...)` only leaves the subshell, so a
# missing-tool check there would print an error and then carry on installing
# an unverified binary, which is the exact failure this whole change exists to
# prevent. Linux ships sha256sum; macOS ships shasum. Neither: refuse.
if command -v sha256sum >/dev/null 2>&1; then SHACMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHACMD="shasum -a 256"
else die "no sha256sum or shasum on this system — cannot verify the download, refusing to install"
fi
sha_of() { $SHACMD "$1" | cut -d' ' -f1; }

echo "Fetching manifest..."
curl -fsSL "$base/version.json" -o "$man" || die "cannot fetch $base/version.json — refusing to install unverified"

# Pull this platform's expected digest out of version.json without needing jq or
# python (neither is guaranteed on a clean macOS or a minimal container): find the
# stanza for our key, then take the quoted value on its "sha256" line.
expected=$(awk -v k="\"$key\"" '
  index($0, k) { f = 1 }
  f && /"sha256"/ { n = split($0, a, "\""); print a[n-1]; exit }
' "$man")
case "$expected" in
  *[!0-9a-f]* | "") die "manifest has no usable sha256 for $key — refusing to install unverified" ;;
esac
[ ${#expected} -eq 64 ] || die "manifest sha256 for $key is malformed — refusing to install unverified"

# Take the URL FROM THE MANIFEST, never build one. The manifest's url now carries
# ?v=<version>, which is what stops Cloudflare handing back the PREVIOUS release's
# binary against the CURRENT release's digest — a stale cache that surfaces as
# "checksum MISMATCH" and reads like a corrupt or tampered download. Same awk
# shape as the digest read above (no jq, no python on a clean macOS). Falls back
# to the constructed path for a manifest that predates the field.
url=$(awk -v k="\"$key\"" '
  index($0, k) { f = 1 }
  f && /"url"/ { n = split($0, a, "\""); print a[n-1]; exit }
' "$man")
case "$url" in
  https://*) ;;
  *) url="$base/dl/privatae-bastion-$key" ;;
esac

echo "Downloading privatae-bastion ($key)..."
curl -fsSL "$url" -o "$tmp" || die "download failed for $key"

actual=$(sha_of "$tmp")
if [ "$actual" != "$expected" ]; then
  die "checksum MISMATCH for privatae-bastion-$key
  expected $expected
  actual   $actual
The downloaded binary is not the one the platform published. Nothing was installed."
fi
echo "Checksum verified ($expected)."

darwin_service=0
if [ "$os" = darwin ] && [ "$networked" = 1 ]; then
  # The launchd daemon runs this program as root, so only root may be able to
  # replace it: a root-owned folder, not /usr/local/bin, which a common package
  # manager hands to the signed-in user on many Macs. `service install` checks
  # the whole path and refuses otherwise.
  darwin_service=1
  appdir="/Library/Application Support/privatae"
  mkdir -p "$appdir/bin"
  chown root:wheel "$appdir" "$appdir/bin"
  chmod 755 "$appdir" "$appdir/bin"
  bin="$appdir/bin/privatae-bastion"
fi

chmod +x "$tmp"
mv "$tmp" "$bin"
if [ "$darwin_service" = 1 ]; then
  chown root:wheel "$bin"
  chmod 755 "$bin"
  # The command people type still works: a link on PATH to the real program.
  # -n replaces an existing link instead of following it: /usr/local/bin may
  # belong to the signed-in user, who could otherwise point the name at a
  # directory and have this root shell create the link inside it.
  mkdir -p /usr/local/bin && ln -sfn "$bin" /usr/local/bin/privatae-bastion
fi
echo "Installed: $bin"

if [ "$os" = linux ] && [ "$root" = 1 ] && command -v systemctl >/dev/null 2>&1; then
  # This unit has NO User= line: the service runs as root. Measured on real
  # installs: `ps` shows root running the bastion, and every such install came
  # from this same script. `run` itself needs no root — the
  # tunnel is userspace — but the networked bastion's ops (observe:*, session:*)
  # do, and a root install is what makes claim-anchor's root check mean
  # something. A single-user machine that wants the local, non-root shape runs
  # the installer WITHOUT sudo and gets the --user path below instead.
  cat > /etc/systemd/system/privatae-bastion.service <<UNIT
[Unit]
Description=Privatae bastion - your secure door into your private mesh (tunnel + lanes)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
# Runs as root on purpose (no User=): the networked bastion's ops need it and the
# anchor claim is root-proved. HOME=/root puts the state under /root/.config.
Environment=HOME=/root
ExecStart=$bin run
Restart=always
RestartSec=2
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  if [ "$networked" = 1 ]; then
    # The mode is box state under the same HOME the unit uses, written by the
    # binary itself so the path is resolved exactly one way.
    HOME=/root "$bin" set-mode networked || die "could not set networked mode"
  fi
  systemctl enable --now privatae-bastion >/dev/null 2>&1 || true
  echo "Service installed + enabled (it restarts until you pair, then connects automatically)."
  echo ""
  if [ "$networked" = 1 ]; then
    echo "Networked bastion. Pair it with YOUR host; the first host paired becomes its anchor:"
    echo "  sudo -H privatae-bastion pair <token>"
    echo "Then enrol your second factor, so you can approve here:"
    echo "  sudo -H privatae-bastion stepup-enroll"
    echo "Every terminal and write waits for your approval, and every later host for your host's."
    echo "(Already paired before this install? Anchor with: sudo -H privatae-bastion claim-anchor)"
  elif [ "$kept_local" = 1 ]; then
    echo "This machine is already paired as a LOCAL bastion, and reinstalling keeps it local."
    echo "To make it a networked server, anchored to the host it serves:"
    echo "  sudo -H privatae-bastion set-mode networked"
    echo "  sudo -H privatae-bastion claim-anchor"
    echo "  sudo -H privatae-bastion stepup-enroll"
    echo "  sudo systemctl restart privatae-bastion"
  else
    echo "Now pair:   sudo -H privatae-bastion pair <token>"
  fi
elif [ "$darwin_service" = 1 ]; then
  # The mode is box state under root's home, where the daemon keeps its state
  # (the daemon's HOME is /var/root), written by the binary itself so the path
  # is resolved exactly one way. Before the service starts, so its first run
  # already sees it.
  HOME=/var/root "$bin" set-mode networked || die "could not set networked mode"
  "$bin" service install || die "could not register the system service"
  echo ""
  echo "Networked bastion, running as a system service (launchd, as root)."
  echo "Pair it with YOUR host; the first host paired becomes its anchor:"
  # The full path, not the name on PATH: /usr/local/bin may belong to the
  # signed-in user, who could point the link at their own program, and this
  # line is run as root.
  echo "  sudo -H '$bin' pair <token>"
  echo "Then enrol your second factor, so you can approve here:"
  echo "  sudo -H '$bin' stepup-enroll"
  echo "Every terminal and write waits for your approval, and every later host for your host's."
  echo "(Already paired before this install? Anchor with: sudo -H '$bin' claim-anchor)"
elif [ "$networked" = 1 ]; then
  die "--networked needs a system service manager: systemd on Linux, launchd on macOS"
else
  case ":$PATH:" in *":$bindir:"*) ;; *) echo "Add to PATH:  export PATH=\"\$PATH:$bindir\"" ;; esac
  echo ""
  if [ "$kept_local" = 1 ]; then
    echo "This machine is already paired as a LOCAL bastion, and reinstalling keeps it local."
    echo "To make it a networked server instead, run the installer again with --networked."
  fi
  echo "Now pair:   privatae-bastion pair <token>"
  echo "Run it:     privatae-bastion run    (Linux non-root: 'loginctl enable-linger \$USER' + a --user unit for boot persistence)"
fi
echo "privatae-bastion is free software under the GNU GPL v3 or later: https://privatae.ai/bastion/LICENSE.txt"
