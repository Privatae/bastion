# Install: the service and the release files

The short version, server and desktop, is in the [README](../README.md#install).

**Your own computer.** Run as yourself, `install.sh` installs the bastion for
the whole machine through sudo: `sudo true` first (one password), then root
fetches the same installer from privatae.ai and runs it with `--personal`, the
pairing code (if any) on its standard input, never in an argument; its
`sudo -H` and `curl -q` read nothing from your home. Your account is recorded
as the machine's owner (`approvals-owner --account`, from `SUDO_UID`; on your
own computer only, never a shared one), so `privatae-bastion ui` opens the
console from it
([console](console.md)). What an earlier, unpaired install for your account
left (its user unit or LaunchAgent and `~/.local/bin/privatae-bastion`) is
removed. `install.ps1` does the same on Windows through one UAC prompt.

**Just your account.** `--just-me` (Windows: `-JustMe`) installs it for your
account alone, and the installer says what that means: any program running as
you can stop it or change what it allows. Where sudo is missing or refuses
(no admin rights, no terminal to ask on), that is what it falls back to, and it
says so. A paired install for your account stays where it is when you
reinstall. Beside a bastion already installed for the whole machine, no second
one is installed for an account: the machine's would refuse to run beside it.

**A server.** Run as root, the installer installs the shared bastion, as
below. `--personal` and `--shared` choose explicitly; their earlier names
`--local` and `--networked` still work.

**Uninstall.** `privatae-bastion uninstall` removes the service and the program
from the installers' places and keeps the state: pairings, keys and the audit
log. `--delete-data` deletes that too, after `delete` is typed at a terminal.
Installed for the whole machine, it needs the administrator; from another
account it removes only that account's own bastion.

A whole-machine install runs as the operating system's own service, whoever is
signed in, and only the machine's administrator can stop it:

- **Linux:** the `systemd` unit `privatae-bastion.service`, as root.
- **macOS:** a `launchd` daemon (`ai.privatae.bastion`) running as root. The
  program goes in `/Library/Application Support/privatae/bin`, which only root
  can change, with a link on `PATH`.
- **Windows:** the service `PrivataeBastion`, running as LocalSystem. The
  program goes in `Program Files\Privatae`, which only administrators can
  change. The installer needs an elevated terminal, and removes the logon task
  an earlier install registered. The agent that serves a shared folder runs
  as the folder's owner, under their own token, while they are signed in to
  the machine; it never runs as LocalSystem, and the bastion writes nothing
  into the folder.

On macOS and Windows, `privatae-bastion service install|uninstall|status` does
the same by hand. An administrator's commands (`sudo -H …` on macOS and Linux,
an Administrator terminal on Windows) act on the service's state. From an
account that does not administer the machine, `pair`, `run`, `status` and
`switch` are refused, on Linux too, so that account does not end up with a
second, empty bastion of its own; `status` there points at `ui`.

An install for one account runs as that account: a systemd user unit, a
LaunchAgent, or on Windows a logon task that starts it each time you sign in.

A Cloud Host's "Set up a bastion" card gives one line that installs, pairs and
starts the bastion: `curl -fsSL https://privatae.ai/bastion/install.sh | PRIVATAE_PAIR_CODE='skp_…' sh`
on macOS and Linux, `& ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Pair 'skp_…'`
on Windows. Installed as you, it then runs as your systemd user unit
`privatae-bastion`, your LaunchAgent `ai.privatae.bastion.user`, or the logon
task. Where it cannot use one, the installer starts the bastion without it and
says how long it will run: on Linux until the machine restarts, on Windows
until you sign out.

Release binaries are served from `https://dl.privatae.ai`. The release manifest
(`version.json`, read by the installers at `https://dl.privatae.ai/version.json`
and by the self-updater at `https://privatae.ai/bastion/version.json`) lists the
current version, the commit it was built from, and the URL plus SHA-256 of
every binary. Beside it, `version.json.<first 16 hex of its sha256>.sig` is an
ed25519 signature over a statement naming the release, its version and the
manifest's sha256, made on the key holder's own computer with
`deploy/release-sign`.
