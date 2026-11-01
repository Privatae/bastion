# M0 gate, Linux: the bastion on its own, on a fresh machine

Run 2026-10-31 on a fresh Ubuntu 24.04.5 virtual machine (qemu, user-mode
networking), with no Host anywhere. Two invented accounts: `tester`, who may
use sudo without a password, and `other`, who may not use sudo. The binary was
built from branch `m0/install-cli-docs` and served, with a manifest and a copy
of `deploy/install.sh` whose two download addresses point at that server, from
the machine running the VM. Nothing else in the installer was changed.

macOS and Windows have not been run yet.

| Gate step | Result |
|---|---|
| Install as a person, `curl … \| sh`, no sudo typed | Installed for the whole machine through sudo; systemd unit running as root; `tester` recorded as the owner |
| `status` from the owner's account | Says the bastion runs for the whole machine and points at `privatae-bastion ui` |
| `ui` from the owner's account | A one-use link; redeemed, it opens a limited session; a second use is refused |
| Limited session | Every page loads; pairing is refused with the administrator's command; Settings shows that command instead of the form |
| `ui` from `other` | Refused: the console opens without sudo only for the owner's account |
| Agents planted: a cron'd `aider`, `claude` in a terminal, a Python program keeping a TLS connection to api.anthropic.com | All listed: `aider` started by a scheduled job, Claude Code started from a terminal, the Python program as a model client talking to api.anthropic.com |
| Stop the cron'd `aider` from the console, from the owner's account, with the owner's code | Stopped; the cron shell and `aider` are gone; Activity says "You stopped aider"; the audit row is in the system log |
| `report` | One Markdown file: summary, agents running now, scheduled jobs, MCP tool servers, changes since the baseline, activity |
| Service log, grep host/lane/pair | No line waiting for or retrying a Host |
| `other` runs the installer | Refused: the machine's bastion is installed for the whole machine and updating it needs sudo; nothing installed |
| Reinstall by `tester` | Service restarted on the new program; the owner record kept |
| `sudo -H privatae-bastion uninstall` | Unit and program removed; state kept (owner record, owner's code, audit log, reports) |

Found and fixed during the run (commit e46bd57): `sudo -v` asked for a
password where the account's sudo rules were not all NOPASSWD, so the installer
fell back to an install for the account; an account without sudo beside the
machine's bastion got a second one that could not run; `uninstall` from that
account was refused.

The first test of the model client used a socket that never started TLS.
api.anthropic.com closed it, and the bastion, which counts open connections
only, did not list it. The second, which keeps a live connection, was listed.

## Transcript (abridged)

```
$ curl -fsSL http://10.0.2.2:8099/install.sh | sh
Installing the bastion for the whole machine, so that no program running as you, an AI agent included, can stop it or change what it allows.
sudo asks for your password once.
Fetching manifest...
Downloading privatae-bastion (linux-amd64)...
Checksum verified (…).
Installed: /usr/local/bin/privatae-bastion
this machine's owner account is tester: `privatae-bastion ui` opens the console from it.
  Anything that stops an agent or widens access still takes the owner's code.

The bastion runs for the whole machine and starts at boot. It is watching the AI agents on this computer now; no Host is needed.
  Open its console:      privatae-bastion ui
  Set up your code, to stop an agent or answer what agents ask (an authenticator app on your phone):
                         sudo -H privatae-bastion stepup-enroll --machine
  Connect a Host, if you run one (optional):  sudo -H privatae-bastion pair <token>

$ ps -o user=,args= -C privatae-bastion
root        /usr/local/bin/privatae-bastion run

$ privatae-bastion status
error: this machine's bastion runs for the whole machine, as a system service.
  Open its console from your own account:  privatae-bastion ui
  Its full status:  sudo -H privatae-bastion status

$ privatae-bastion ui
opening the local UI: http://127.0.0.1:7877
could not open a browser (exec: "xdg-open": executable file not found in $PATH).
Paste this into one, within a minute:
  http://127.0.0.1:7877/?k=…

redeem=303   GET /=200  /setup=200  /approvals=200  /activity=200  /machine=200
POST /setup/pair=403  From your own account the console does not do this: it widens what reaches this machine and takes no code. The machine's administrator does it: sudo -H privatae-bastion ui
reuse of the link=403

(other)$ privatae-bastion ui
error: this machine's console opens without sudo only for its owner's account (tester), not other

$ sudo -H privatae-bastion agents
aider: 2 sessions
  aider in tester
      in /home/tester · started 1m ago · started by a scheduled job · as tester · pid 2018
  …
Claude Code: 1 session
  Claude Code in tester
      in /home/tester · started 1m ago · started from a terminal here · as tester · pid 1903

$ sudo -H privatae-bastion agents --json   (the model client)
2220 llm-client  evidence: model-traffic api.anthropic.com (verified), model-endpoint api.anthropic.com (verified)

POST /agent/stop pid=2018 with the owner's code → 200 "stopped aider (pid 2018) running on this machine."
$ ps -p 2017,2018        → process tree gone
$ sudo -H privatae-bastion activity
Oct 31 03:52  You stopped aider (pid 2018) running on this machine.
journal: privatae-bastion-audit: {"decision":"You stopped aider (pid 2018) running on this machine.","op":"local_stop",…}

$ sudo -H privatae-bastion report
report written to /root/.config/privatae-bastion/reports/report-2026-10-31-035215.md
# AI agents on m0-gate / ## Summary / ## Agents running now / ## Scheduled jobs that start an agent /
## MCP tool servers / ## Changes since the baseline / ## Activity

$ journalctl -u privatae-bastion | grep -iE 'host|lane|pair'
privatae-bastion: no Host connected: watching this machine on its own. Open the console with `privatae-bastion ui`.
(the rest are systemd's start lines)

(other)$ curl -fsSL http://10.0.2.2:8099/install.sh | sh
… ERROR: this machine's bastion is installed for the whole machine, and updating it needs an account that may use sudo, in a terminal. Nothing was installed.

$ sudo -H privatae-bastion uninstall
  stopped the system service privatae-bastion
  removed /usr/local/bin/privatae-bastion
Kept /root/.config/privatae-bastion: its pairings, keys and the audit log of what Hosts and agents did here.
The bastion is uninstalled.
```
