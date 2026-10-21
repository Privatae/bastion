#!/bin/sh
# privatae-bastion installer (macOS / Linux). Installs the binary AND — on Linux as root —
# the always-on systemd service, and with --networked on macOS a launchd daemon
# running as root, so onboarding a node is two commands:
#   curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
#   sudo -H privatae-bastion pair <token>
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

# --networked: install the NETWORKED bastion — a root-owned
# service on a machine several people share, anchored to one host that approves
# every further pairing. Everything else is the LOCAL bastion: one host, and on a
# home machine it runs as the user. Usage:  curl ... | sudo sh -s -- --networked
networked=0
for a in "$@"; do
  case "$a" in
    --networked) networked=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
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
    echo "Networked bastion. Anchor it to YOUR host first (root, one step):"
    echo "  sudo -H privatae-bastion claim-anchor"
    echo "  (add --host <name> if this machine already serves several Hosts)"
    echo "Every host paired after that waits, pending, until your host approves it."
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
  echo "Anchor it to YOUR host first (root, one step):"
  # The full path, not the name on PATH: /usr/local/bin may belong to the
  # signed-in user, who could point the link at their own program, and this
  # line is run as root.
  echo "  sudo -H '$bin' claim-anchor"
  echo "  (add --host <name> if this machine already serves several Hosts)"
  echo "Every host paired after that waits, pending, until your host approves it."
elif [ "$networked" = 1 ]; then
  die "--networked needs a system service manager: systemd on Linux, launchd on macOS"
else
  case ":$PATH:" in *":$bindir:"*) ;; *) echo "Add to PATH:  export PATH=\"\$PATH:$bindir\"" ;; esac
  echo ""
  echo "Now pair:   privatae-bastion pair <token>"
  echo "Run it:     privatae-bastion run    (Linux non-root: 'loginctl enable-linger \$USER' + a --user unit for boot persistence)"
fi
echo "privatae-bastion is free software under the GNU GPL v3 or later: https://privatae.ai/bastion/LICENSE.txt"
