# Install: the service and the release files

The short version, server and desktop, is in the [README](../README.md#install).

A networked install runs as the operating system's own service, whoever is
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
the same by hand. An administrator's commands (`sudo -H …` on macOS, an
Administrator terminal on Windows) act on the service's state. From an account
that does not administer the machine, `pair`, `run`, `status` and `switch` are
refused, so that account does not end up with a second, empty bastion of its
own.

A local install runs as you. On Windows the installer registers a logon task
that starts it each time you sign in.

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
