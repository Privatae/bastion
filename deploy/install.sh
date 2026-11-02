#!/bin/sh
# privatae-bastion installer (macOS / Linux).
#
# On your own computer:   curl -fsSL https://privatae.ai/bastion/install.sh | sh
# It installs the bastion for the WHOLE MACHINE, as a system service (systemd on
# Linux, launchd on macOS), so that no program running as you, an AI agent
# included, can stop it or change what it allows. sudo asks for your password
# once. Your own computer is the default ("personal": one Host at most, chosen at
# the machine), and your account opens the console without sudo:
# privatae-bastion ui. It watches the AI agents on the machine at once; no Host is
# needed.
#
# On a server:   curl -fsSL https://privatae.ai/bastion/install.sh | sudo sh
# Run as root, it installs the SHARED bastion (several Hosts, the first one paired
# is in charge), as before:   sudo -H privatae-bastion pair <token>
#
# --just-me installs it for your own account only, with no sudo. Any program
# running as you can then stop it; the installer says so. Without sudo, or when
# sudo refuses, that is what it falls back to, and it says that too.
# --personal / --shared choose the kind of machine (also spelled --local /
# --networked, their earlier names).
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
just_me=0
code_on_stdin=0
for a in "$@"; do
  case "$a" in
    --networked|--shared) networked=1 ;;
    --local|--personal) local=1 ;;
    --just-me) just_me=1 ;;
    # Internal: the whole-machine step this script runs through sudo
    # (elevate_whole_machine) hands the pairing code on standard input, never
    # in its arguments.
    --pair-code-on-stdin) code_on_stdin=1 ;;
    # An unknown argument is never echoed: it may be a pairing code given in
    # the wrong place, and a log of the failed install must not hold it.
    *) echo "ERROR: unknown option. This installer takes --personal, --shared or --just-me; a pairing code goes in PRIVATAE_PAIR_CODE, as your Host's card shows. Nothing was installed." >&2; exit 2 ;;
  esac
done
if [ "$networked" = 1 ] && [ "$local" = 1 ]; then
  echo "ERROR: --shared and --personal contradict each other; pass one" >&2; exit 2
fi
if [ "$just_me" = 1 ] && [ "$(id -u)" = 0 ]; then
  echo "ERROR: --just-me installs the bastion for your own account; run it without sudo. Nothing was installed." >&2; exit 2
fi
if [ "$just_me" = 1 ] && [ "$networked" = 1 ]; then
  echo "ERROR: a shared machine's bastion runs for the whole machine; --just-me and --shared contradict each other" >&2; exit 2
fi
if [ "$code_on_stdin" = 1 ]; then
  if [ "$(id -u)" != 0 ] || [ -n "$pair_given" ]; then
    echo "ERROR: unknown option. Nothing was installed." >&2; exit 2
  fi
  IFS= read -r pair_code || true
  pair_given=1
  case "$pair_code" in
    skp_*[!A-Za-z0-9_-]* | skp_) pair_code="" ;;
    skp_?*) ;;
    *) pair_code="" ;;
  esac
  [ -n "$pair_code" ] || { echo "ERROR: the pairing code did not arrive. Nothing was installed." >&2; exit 2; }
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
Description=Privatae bastion - watches the AI agents in this account
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

# record_owner BIN ROOT OS: run through sudo from a person's account on their
# own computer, record that account as the machine's owner, whose own account
# then opens the console without sudo (privatae-bastion ui). SUDO_UID is set by
# sudo itself. Not on a shared machine: there the console stays the
# administrator's (sudo -H privatae-bastion ui), so no agent running as the
# account that ran sudo can reach it. A second administrator's reinstall leaves
# the first owner in place; the bastion says so.
record_owner() {
  ro_bin=$1; ro_root=$2; ro_os=$3
  [ "$ro_root" = 1 ] || return 0
  [ "$networked" != 1 ] || return 0
  case "${SUDO_UID-}" in ""|0|*[!0-9]*) return 0 ;; esac
  pair_as "$ro_root" "$ro_os" "$ro_bin" approvals-owner --account "$SUDO_UID" </dev/null || \
    echo "NOTE: your account was not recorded as this machine's owner (the reason is above); open the console with: sudo -H privatae-bastion ui" >&2
}

# whole_machine_next BIN: what to do next on a person's own computer, the
# bastion installed for the whole machine and no Host connected.
whole_machine_next() {
  echo "The bastion runs for the whole machine and starts at boot. It is watching the AI agents on this computer now; no Host is needed."
  echo "  Open its console:      privatae-bastion ui"
  case "$(uname -s)" in
    Darwin) wmn_state="/var/root/Library/Application Support/privatae-bastion" ;;
    *) wmn_state=/root/.config/privatae-bastion ;;
  esac
  [ -f "$wmn_state/machine-factor/stepup.json" ] && return 0
  echo "  Set up your code, to stop an agent or answer what agents ask (an authenticator app on your phone):"
  echo "                         sudo -H privatae-bastion stepup-enroll --machine"
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

# whole_machine_script is what the whole-machine step runs as root: this same
# installer, fetched by root from the one place it is published. A script
# piped to sh cannot hand itself on, and a copy this account wrote would be a
# file this account could change before root ran it. Hardcoded, like $base.
whole_machine_script="https://privatae.ai/bastion/install.sh"

# account_install_paired: 0 when this account already has a bastion of its own
# that is paired. An upgrade keeps it where it is: moved to the whole machine,
# its pairings would stay behind in this account.
account_install_paired() {
  case "$(uname -s)" in
    Darwin) aip_dir="${HOME}/Library/Application Support/privatae-bastion" ;;
    *) aip_dir="${XDG_CONFIG_HOME:-$HOME/.config}/privatae-bastion" ;;
  esac
  [ -f "$aip_dir/config.json" ] && return 0
  for aip_f in "$aip_dir"/pairings/*.json; do [ -f "$aip_f" ] && return 0; done
  return 1
}

# elevate_whole_machine: install for the whole machine through sudo. Returns 3
# when sudo is missing or refuses (no admin rights, no terminal to ask on, a
# wrong password): nothing was installed. Otherwise the root step's own exit
# status. The pairing code reaches the root step on standard input, never in
# an argument, where the process list would show it.
elevate_whole_machine() {
  command -v sudo >/dev/null 2>&1 || return 3
  echo "Installing the bastion for the whole machine, so that no program running as you, an AI agent included, can stop it or change what it allows."
  echo "sudo asks for your password once."
  # `sudo true`, not `sudo -v`: -v asks for a password unless every sudo rule
  # of the account is NOPASSWD (sudoers verifypw), so an account that may run
  # anything without one was asked anyway, and fell back to itself where no
  # terminal could answer.
  sudo -p '[bastion] sudo password for %u: ' true </dev/null || return 3
  ew_kind=--personal
  [ "$networked" = 1 ] && ew_kind=--shared
  # -H and curl -q: root's step reads nothing from this account's home. A sudo
  # configured to keep HOME (env_keep) would otherwise have root's curl
  # read this account's ~/.curlrc, which can point the fetch at another server
  # (resolve, proxy) and switch off its certificate check: a file this account
  # can change, deciding what root runs.
  ew_cmd='f=$(mktemp) || exit 1; if curl -q -fsSL "$1" -o "$f"; then shift; /bin/sh "$f" "$@"; rc=$?; else echo "ERROR: could not fetch $1. Nothing was installed." >&2; rc=1; fi; rm -f "$f"; exit $rc'
  ew_rc=0
  if [ -n "$pair_code" ]; then
    printf '%s\n' "$pair_code" | sudo -H /bin/sh -c "$ew_cmd" sh "$whole_machine_script" "$ew_kind" --pair-code-on-stdin || ew_rc=$?
  else
    sudo -H /bin/sh -c "$ew_cmd" sh "$whole_machine_script" "$ew_kind" </dev/null || ew_rc=$?
  fi
  # 3 means sudo refused (above); the root step's own failure is never read
  # as that.
  [ "$ew_rc" = 3 ] && ew_rc=1
  return "$ew_rc"
}

# account_copy_cleanup: what an earlier install for this account alone left
# that would run a second bastion beside the machine's: its unit or LaunchAgent
# and its program. Its state, pairings included, stays in the account. Reached
# when that install held no pairing, or when the machine already has a
# bastion for the whole machine, beside which it could not run anyway.
account_copy_cleanup() {
  acc_unit="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/privatae-bastion.service"
  if [ -f "$acc_unit" ]; then
    systemctl --user disable --now privatae-bastion >/dev/null 2>&1 || true
    rm -f "$acc_unit"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    echo "Removed this account's own bastion service; the machine's replaces it."
  fi
  acc_plist="$HOME/Library/LaunchAgents/ai.privatae.bastion.user.plist"
  if [ -f "$acc_plist" ]; then
    /bin/launchctl bootout "gui/$(id -u)/ai.privatae.bastion.user" >/dev/null 2>&1 || true
    rm -f "$acc_plist"
    echo "Removed this account's own bastion LaunchAgent; the machine's replaces it."
  fi
  if [ -f "$HOME/.local/bin/privatae-bastion" ] && [ ! -L "$HOME/.local/bin/privatae-bastion" ]; then
    rm -f "$HOME/.local/bin/privatae-bastion"
    echo "Removed $HOME/.local/bin/privatae-bastion, an earlier copy that would come first on PATH."
  fi
  if [ "$(uname -s)" = Linux ]; then stop_user_copies; fi
}

# machine_install_present: 0 when this machine's bastion is already installed
# for the whole machine. A second one for an account beside it would only be
# refused (the bastion's own guard), so none is installed.
machine_install_present() {
  case "$(uname -s)" in
    Darwin) [ -f /Library/LaunchDaemons/ai.privatae.bastion.plist ] ;;
    *) [ -f /etc/systemd/system/privatae-bastion.service ] ;;
  esac
}

# Not root: the whole machine, through sudo, unless this account's own bastion
# is asked for (--just-me) or is already paired. Where sudo cannot be used,
# this account, and the installer says what that means; but never beside a
# bastion installed for the whole machine.
kept_account=0
fell_back=0
if [ "$root" != 1 ] && [ "$just_me" = 1 ] && machine_install_present; then
  echo "ERROR: this machine's bastion is installed for the whole machine, and a second one for your account would be refused beside it. Its console opens from its owner's account with: privatae-bastion ui. Nothing was installed." >&2
  exit 1
fi
if [ "$root" != 1 ] && [ "$just_me" != 1 ]; then
  if account_install_paired && ! machine_install_present; then
    kept_account=1
  else
    ew_rc=0
    elevate_whole_machine || ew_rc=$?
    case "$ew_rc" in
      0) account_copy_cleanup; exit 0 ;;
      3) if machine_install_present; then
           echo "ERROR: this machine's bastion is installed for the whole machine, and updating it needs an account that may use sudo, in a terminal. Nothing was installed." >&2
           exit 1
         fi
         fell_back=1
         echo "sudo could not be used here, so the bastion is installed for your account only." >&2 ;;
      *) exit "$ew_rc" ;;
    esac
  fi
fi

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
tmp=$(mktemp); man=$(mktemp); vdir=$(mktemp -d)
# Any exit before the final mv must leave nothing behind and install nothing:
# this script is piped to `sudo sh`, so a partial run is a root-privileged
# partial install.
trap 'rm -f "$tmp" "$man"; rm -rf "$vdir"' EXIT INT TERM

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

# ── the release signature ──────────────────────────────────────────────────
#
# The manifest names each binary's digest, and the download is checked against
# it. The manifest itself is signed with a release key whose public half is
# pinned here, the same keys a running bastion checks every update with
# (client-go/release_sign.go productionReleaseKeys; install_sig_sh_test.go
# holds the two to each other). So a copy of this script read on GitHub and run
# from there as root, or with --just-me, installs only a release we signed
# (possibly an older one), whatever the download host serves. Run without
# sudo, the copy does not install for the whole machine itself: its root step
# fetches this installer from the website again (whole_machine_script) and
# runs that. The signature is over one statement, as verifyReleaseSignature
# builds it: privatae-release-signature-v1, the kind, the version, and the
# manifest's sha256, a line each; it sits beside the manifest at
# version.json.<the first 16 hex of that sha256>.sig, in base64.
#
# Checked with an openssl that does Ed25519 (OpenSSL 3, on most Linux; the
# openssl@3 Homebrew installs on a Mac). A probe signature made for this tells
# "this openssl cannot check" from "the signature is wrong": the first prints a
# note and keeps the digest check alone, which is what the script did before;
# the second refuses to install.
RELEASE_KEYS='MCowBQYDK2VwAyEAtWOyZm38DwTwbawSnvExQG/CQsVJBKYWc46arCBZj9E= MCowBQYDK2VwAyEACKL+J0VSdqrfY4AmxChvylJ1ha4e8GvcrYF2o17Ah+g='
SIG_PROBE_KEY='MCowBQYDK2VwAyEA1TRy5NeI2n7tieFf6cHe5VE69SV0XL7Vx4k6EwFlFFk='
SIG_PROBE_SIG='Do3fnwjyv8QgR+9sJcc0A3Sr0XzSKqBW8DK8kzaJL29tS8KxuStc2tp+HheJvoGwXmrH2kg7YN+yDLKVDnDqDQ=='

# release_signature_check <manifest> <empty scratch dir>: returns when the
# manifest's signature verifies, or when no openssl here can check one (said);
# exits when it does not verify.
release_signature_check() {
  rs_man=$1 rs_dir=$2
  rs_pem() { printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$1" > "$2"; }
  rs_ssl=""
  rs_pem "$SIG_PROBE_KEY" "$rs_dir/probe.pem"
  printf 'privatae-installer-probe-v1\n' > "$rs_dir/probe.msg"
  printf 'privatae-installer-probe-v0\n' > "$rs_dir/probe.other"
  # The probe signature must verify over its message and not over another: an
  # openssl that passes every signature is no check, and is set aside like one
  # that cannot check, never taken for one.
  for c in openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    command -v "$c" >/dev/null 2>&1 || continue
    printf '%s' "$SIG_PROBE_SIG" | "$c" base64 -d -A -out "$rs_dir/probe.sig" 2>/dev/null || continue
    if "$c" pkeyutl -verify -pubin -inkey "$rs_dir/probe.pem" -rawin -in "$rs_dir/probe.msg" \
        -sigfile "$rs_dir/probe.sig" >/dev/null 2>&1 &&
      ! "$c" pkeyutl -verify -pubin -inkey "$rs_dir/probe.pem" -rawin -in "$rs_dir/probe.other" \
        -sigfile "$rs_dir/probe.sig" >/dev/null 2>&1; then
      rs_ssl=$c; break
    fi
  done
  if [ -z "$rs_ssl" ]; then
    echo "NOTE: no openssl here can check an Ed25519 signature, so the release's signature is not checked;"
    echo "      the download is still checked against the manifest's digest, fetched over HTTPS."
    if [ "$os" = darwin ]; then
      echo "      To check the signature too, install OpenSSL 3 (brew install openssl@3) and run this again."
    else
      echo "      To check the signature too, install OpenSSL 3 from your distribution and run this again."
    fi
    return 0
  fi
  rs_sum=$(sha_of "$rs_man")
  case "$rs_sum" in *[!0-9a-f]* | "") die "cannot take the manifest's digest — refusing to install unverified" ;; esac
  rs_ver=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$rs_man" | head -n 1)
  case "$rs_ver" in
    "" | *[!0-9A-Za-z.+-]*) die "the manifest names no usable version — refusing to install unverified" ;;
  esac
  rs_short=$(printf '%s' "$rs_sum" | cut -c1-16)
  curl -fsSL --max-filesize 4096 "$base/version.json.$rs_short.sig" -o "$rs_dir/sig.b64" \
    || die "cannot fetch the release's signature ($base/version.json.$rs_short.sig) — refusing to install unverified"
  tr -d ' \r\n' < "$rs_dir/sig.b64" | "$rs_ssl" base64 -d -A -out "$rs_dir/sig" 2>/dev/null \
    || die "the release's signature is malformed — refusing to install"
  [ "$(wc -c < "$rs_dir/sig" | tr -d ' ')" = 64 ] || die "the release's signature is malformed — refusing to install"
  printf 'privatae-release-signature-v1\nbastion\n%s\n%s\n' "$rs_ver" "$rs_sum" > "$rs_dir/statement"
  for k in $RELEASE_KEYS; do
    rs_pem "$k" "$rs_dir/key.pem"
    if "$rs_ssl" pkeyutl -verify -pubin -inkey "$rs_dir/key.pem" -rawin -in "$rs_dir/statement" \
        -sigfile "$rs_dir/sig" >/dev/null 2>&1; then
      echo "Release signature verified (version $rs_ver)."
      return 0
    fi
  done
  die "the release's signature does not verify against the pinned release keys — refusing to install"
}

echo "Fetching manifest..."
curl -fsSL "$base/version.json" -o "$man" || die "cannot fetch $base/version.json — refusing to install unverified"
release_signature_check "$man" "$vdir"

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
if [ "$os" = darwin ] && [ "$root" = 1 ]; then
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
Description=Privatae bastion - watches the AI agents on this machine
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
  systemctl enable privatae-bastion >/dev/null 2>&1 || true
  # restart, not start: a reinstall must run the new program.
  systemctl restart privatae-bastion >/dev/null 2>&1 || true
  record_owner "$bin" "$root" "$os"
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
    whole_machine_next "$bin"
    echo "  Connect a Host, if you run one (optional):  sudo -H privatae-bastion pair <token>"
  fi
elif [ "$darwin_service" = 1 ]; then
  # The mode is box state under root's home, where the daemon keeps its state
  # (the daemon's HOME is /var/root), written by the binary itself so the path
  # is resolved exactly one way. Before the service starts, so its first run
  # already sees it.
  if [ "$networked" = 1 ]; then
    HOME=/var/root "$bin" set-mode networked || die "could not set networked mode"
  fi
  "$bin" service install || die "could not register the system service"
  record_owner "$bin" "$root" "$os"
  echo ""
  if [ -z "$pair_code" ] && [ "$networked" != 1 ]; then
    whole_machine_next "$bin"
  elif [ -z "$pair_code" ]; then
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
  if [ "$kept_account" = 1 ]; then
    echo "This account's own bastion is already paired, so it stays installed for this account."
    echo "To move it to the whole machine: disconnect its Host (privatae-bastion unpair <host>), run this"
    echo "installer again, and connect the Host again with: sudo -H privatae-bastion pair <token>"
  fi
  echo "WARNING: installed for your account only. Any program running as you, an AI agent included, can stop"
  echo "  the bastion or change what it allows."
  if [ "$just_me" = 1 ]; then
    echo "  To install it for the whole machine instead, run this installer again without --just-me."
  elif [ "$fell_back" = 1 ]; then
    echo "  To install it for the whole machine, run this installer again in a terminal, from an account that may use sudo."
  fi
  if [ -z "$pair_code" ]; then
    if start_how=$(start_bastion "$bin" "$root" "$os"); then
      echo "$start_how"
      echo "It is watching the AI agents in this account now; no Host is needed. Open its console:  $bin ui"
    else
      echo "Start it with:  $bin run" >&2
    fi
    echo "Connect a Host, if you run one (optional):  $bin pair <token>"
  fi
fi
if [ -n "$pair_code" ]; then
  echo ""
  pair_and_start "$bin" "$pair_code" "$root" "$os" || exit 1
fi
echo "privatae-bastion is free software under the GNU GPL v3 or later: https://privatae.ai/bastion/LICENSE.txt"
