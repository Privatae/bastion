#!/bin/sh
# privatae-bastion installer (macOS / Linux). Run as root (a server), it installs the
# NETWORKED bastion as a system service (systemd on Linux, launchd on macOS), and the
# first host paired anchors it, so onboarding a server is two commands:
#   curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
#   sudo -H privatae-bastion pair <token>
# Run as your own user (a desktop), it installs the LOCAL bastion for that user.
#
# PRIVATAE_PAIR_CODE='<code>' pairs as well, with the code from your Host's "Set
# up a bastion" card, and starts the bastion so it serves now and after a
# restart. The one line the card gives is
#   curl -fsSL https://privatae.ai/bastion/install.sh | PRIVATAE_PAIR_CODE='skp_…' sh
#
set -e
# The pairing code comes from the environment, never from an argument: an
# argument sits in this shell's command line for the whole install, where any
# user of this machine can read it with ps, and one at the same address could
# redeem it first. A process's environment is readable only by its owner and
# root. It is read here, before this script starts any program, and unset at
# once, so no program it starts inherits it. Never echoed: it holds the token.
pair_code=${PRIVATAE_PAIR_CODE-}
pair_given=${PRIVATAE_PAIR_CODE+1}
unset PRIVATAE_PAIR_CODE
if [ -n "$pair_given" ]; then
  # skp_ and base64url: anything else is a line that lost part of the code.
  case "$pair_code" in
    skp_*[!A-Za-z0-9_-]* | skp_) pair_code="" ;;
    skp_?*) ;;
    *) pair_code="" ;;
  esac
  if [ -z "$pair_code" ]; then
    echo "ERROR: PRIVATAE_PAIR_CODE is not a pairing code. Copy the whole line from your Host's card again (the code starts skp_). Nothing was installed." >&2
    exit 2
  fi
fi
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
    # An unknown argument is never echoed: it may be a pairing code given in
    # the wrong place, and a log of the failed install must not hold it.
    *) echo "ERROR: unknown option. This installer takes --networked or --local; a pairing code goes in PRIVATAE_PAIR_CODE, as your Host's card shows. Nothing was installed." >&2; exit 2 ;;
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

# pair_as ROOT OS BIN ARGS...: run the bastion as the state it serves. As
# root that is the service's HOME (the unit's /root, launchd's /var/root),
# whatever HOME `sudo` left behind; as yourself it is your own.
pair_as() {
  pa_root=$1; pa_os=$2; shift 2
  if [ "$pa_root" = 1 ]; then
    if [ "$pa_os" = darwin ]; then HOME=/var/root "$@"; else HOME=/root "$@"; fi
  else
    "$@"
  fi
}

# bastion_copy PID: 0 when PID is a process of this user running a program
# named privatae-bastion, from any path, including one replaced on disk since
# it started. A process that has exited, or another user's, is not.
bastion_copy() {
  [ -O "/proc/$1" ] || return 1
  bc_exe=$(readlink "/proc/$1/exe" 2>/dev/null) || return 1
  case "${bc_exe##*/}" in
    "privatae-bastion" | "privatae-bastion (deleted)") return 0 ;;
  esac
  return 1
}

# stop_user_copies: stop every copy of this user's bastion (Linux), as
# install.ps1 does on Windows: one left running in a terminal, from an older
# install or another path. `run` holds the machine's run lock, so the copy the
# service starts would only wait behind it, and that copy never reads the new
# pairing; an older build would fail on 127.0.0.1:7878 and restart for ever.
# Asked to stop, then killed after 10 seconds. Says on stderr how many.
stop_user_copies() {
  suc_pids=""
  for suc_d in /proc/[0-9]*; do
    suc_pid=${suc_d#/proc/}
    bastion_copy "$suc_pid" || continue
    kill "$suc_pid" 2>/dev/null && suc_pids="$suc_pids $suc_pid"
  done
  [ -n "$suc_pids" ] || return 0
  set -- $suc_pids
  echo "Stopped $# copy(ies) of the bastion running outside its service (a terminal, or another install)." >&2
  for suc_i in 1 2 3 4 5 6 7 8 9 10; do
    suc_left=""
    for suc_pid in $suc_pids; do bastion_copy "$suc_pid" && suc_left="$suc_left $suc_pid"; done
    [ -n "$suc_left" ] || return 0
    sleep 1
  done
  for suc_pid in $suc_left; do kill -9 "$suc_pid" 2>/dev/null || true; done
}

# user_unit_stays_up: 0 when the user unit privatae-bastion is running and
# has kept the same process across a few seconds, longer than its
# RestartSec, so a copy that fails at start and is restarted is caught.
# Otherwise says what systemd shows, on stderr.
user_unit_stays_up() {
  sleep 1
  uu_first=$(systemctl --user show -p MainPID --value privatae-bastion 2>/dev/null) || uu_first=""
  sleep 4
  uu_pid=$(systemctl --user show -p MainPID --value privatae-bastion 2>/dev/null) || uu_pid=""
  uu_state=$(systemctl --user show -p ActiveState --value privatae-bastion 2>/dev/null) || uu_state=""
  uu_sub=$(systemctl --user show -p SubState --value privatae-bastion 2>/dev/null) || uu_sub=""
  if [ "$uu_state" = active ] && [ "$uu_sub" = running ] && [ -n "$uu_pid" ] && [ "$uu_pid" != 0 ] && [ "$uu_pid" = "$uu_first" ]; then
    return 0
  fi
  echo "The bastion's user service privatae-bastion is not staying up (systemd shows it ${uu_state:-unknown}/${uu_sub:-unknown}, and it has restarted)." >&2
  echo "Its log says why:  journalctl --user -u privatae-bastion" >&2
  return 1
}

# start_bastion BIN ROOT OS: start, or restart, the bastion so it serves every
# pairing now and starts again by itself. A running bastion reads a new
# pairing at its next start, so a restart is what a fresh pairing needs.
# Prints one plain sentence saying how it will run.
start_bastion() {
  sb_bin=$1; sb_root=$2; sb_os=$3
  if [ "$sb_root" = 1 ] && [ "$sb_os" = linux ] && command -v systemctl >/dev/null 2>&1; then
    systemctl restart privatae-bastion || return 1
    echo "The bastion runs as the system service privatae-bastion, and starts at boot."
    return 0
  fi
  if [ "$sb_root" = 1 ] && [ "$sb_os" = darwin ] && [ -f /Library/LaunchDaemons/ai.privatae.bastion.plist ]; then
    /bin/launchctl kickstart -k system/ai.privatae.bastion || return 1
    echo "The bastion runs as the system service ai.privatae.bastion, and starts at boot."
    return 0
  fi
  if [ "$sb_root" != 1 ] && [ "$sb_os" = linux ] && command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    # A systemd user unit: yours, no root. It starts when you sign in; with
    # lingering on, at boot and after you sign out as well.
    sb_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
    mkdir -p "$sb_dir"
    cat > "$sb_dir/privatae-bastion.service" <<UNIT
[Unit]
Description=Privatae bastion - serves this machine to your Hosts (tunnel + lanes)
[Service]
Type=simple
ExecStart=$sb_bin run
Restart=always
RestartSec=2
[Install]
WantedBy=default.target
UNIT
    systemctl --user daemon-reload && systemctl --user enable privatae-bastion >/dev/null 2>&1 || return 1
    # Its own copy first, then every other: what is left running after this
    # is only what the unit starts.
    systemctl --user stop privatae-bastion >/dev/null 2>&1 || true
    stop_user_copies
    systemctl --user restart privatae-bastion || return 1
    user_unit_stays_up || return 1
    if loginctl enable-linger "$(id -un)" >/dev/null 2>&1; then
      echo "The bastion runs as your systemd user service privatae-bastion, and starts at boot."
    else
      echo "The bastion runs as your systemd user service privatae-bastion while you are signed in."
      echo "To keep it running at boot and after you sign out:  sudo loginctl enable-linger $(id -un)"
    fi
    return 0
  fi
  if [ "$sb_root" != 1 ] && [ "$sb_os" = darwin ]; then
    # A LaunchAgent: yours, no root, started each time you log in.
    sb_plist="$HOME/Library/LaunchAgents/ai.privatae.bastion.user.plist"
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$sb_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.privatae.bastion.user</string>
  <key>ProgramArguments</key><array><string>$sb_bin</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST
    /bin/launchctl bootout "gui/$(id -u)/ai.privatae.bastion.user" >/dev/null 2>&1 || true
    /bin/launchctl bootstrap "gui/$(id -u)" "$sb_plist" || return 1
    echo "The bastion runs as your LaunchAgent ai.privatae.bastion.user, and starts each time you log in."
    return 0
  fi
  # No service manager this script can use: run it now, detached, once every
  # other copy of it has stopped (stop_user_copies says why).
  if [ "$sb_os" = linux ] && [ "$sb_root" != 1 ]; then stop_user_copies; fi
  nohup "$sb_bin" run >/dev/null 2>&1 &
  sb_pid=$!
  sleep 3
  if [ "$sb_os" = linux ] && ! bastion_copy "$sb_pid"; then
    echo "The bastion stopped as soon as it started. Run it in a terminal to see why:  $sb_bin run" >&2
    return 1
  fi
  echo "The bastion is running, until this machine restarts. Start it again with:  $sb_bin run"
}

# pair_and_start BIN CODE ROOT OS: pair with CODE, handed to `pair -` on
# standard input and never as an argument, where the process list would show
# it. Then start the bastion and show its status. `pair` exits 3 when this
# machine is already paired with that Host, which is success here too.
pair_and_start() {
  ps_bin=$1; ps_code=$2; ps_root=$3; ps_os=$4
  ps_rc=0
  printf '%s\n' "$ps_code" | pair_as "$ps_root" "$ps_os" "$ps_bin" pair - || ps_rc=$?
  case "$ps_rc" in
    0) ps_done="This machine is paired." ;;
    3) ps_done="This machine was already paired with this Host; nothing changed there." ;;
    *) echo "ERROR: pairing did not finish (the reason is above). The bastion is installed; nothing else changed." >&2
       return 1 ;;
  esac
  ps_how=$(start_bastion "$ps_bin" "$ps_root" "$ps_os") || {
    echo "ERROR: $ps_done But the bastion did not start. Start it with:  $ps_bin run" >&2
    return 1
  }
  sleep 2
  pair_as "$ps_root" "$ps_os" "$ps_bin" status || true
  echo ""
  echo "$ps_done $ps_how"
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
  if [ -n "$pair_code" ]; then
    :
  elif [ "$networked" = 1 ]; then
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
  if [ -z "$pair_code" ]; then
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
  fi
elif [ "$networked" = 1 ]; then
  die "--networked needs a system service manager: systemd on Linux, launchd on macOS"
else
  case ":$PATH:" in *":$bindir:"*) ;; *) echo "Add to PATH:  export PATH=\"\$PATH:$bindir\"" ;; esac
  echo ""
  if [ "$kept_local" = 1 ]; then
    echo "This machine is already paired as a LOCAL bastion, and reinstalling keeps it local."
    echo "To make it a networked server instead, run the installer again with --networked."
  fi
  if [ -z "$pair_code" ]; then
  echo "Now pair:   privatae-bastion pair <token>"
  echo "Run it:     privatae-bastion run    (Linux non-root: 'loginctl enable-linger \$USER' + a --user unit for boot persistence)"
  fi
fi
if [ -n "$pair_code" ]; then
  echo ""
  pair_and_start "$bin" "$pair_code" "$root" "$os" || exit 1
fi
echo "privatae-bastion is free software under the GNU GPL v3 or later: https://privatae.ai/bastion/LICENSE.txt"
