# M1 gate, Linux: an agent on the machine asks, the machine's owner answers

Run 2026-11-02 on the Ubuntu 24.04 virtual machine the [M0 gate](m0-gate-linux-2026-10-31.md)
used (qemu, user-mode networking), with no Host anywhere. The bastion is
installed for the whole machine (its systemd unit, running as root), and
`tester` is recorded as the machine's owner. `other` is a second account with
no sudo. The binary was built from the 0.61.0 release branch just before this
record was added (`privatae-bastion version`: `0.61.0+090bdb8`) and put in
place of the installed one.

The asker is an AI agent the bastion recognises: a program at
`~/.local/bin/claude`, which it lists as Claude Code, started from a remote
login (ssh). The target is `aider`, started every minute by a cron job in
`tester`'s crontab. Both are stand-ins (`sh` and `sleep` under those names),
which is how the bastion meets them anyway: by the program a process runs and
how it was started.

macOS and Windows have not been run. On Windows an agent cannot ask yet,
because the ask socket is Unix only ([STATUS](../STATUS.md)).

| Gate step | Result |
|---|---|
| The agent lists the AI agents on the machine (`agents --json`) | `aider` (started by a scheduled job) and Claude Code (started from a remote login), with pids and accounts |
| The agent asks to stop `aider` (`stop <pid> --json`) | A request id and state `waiting`; the request names the agent that asked and the target |
| The owner lists what waits, from their own account (`approvals --machine`) | The request, in the same words |
| The owner approves with a wrong code | Refused; nothing stopped |
| The owner approves with the code from their authenticator (`approve --machine <id>`) | Approved, and the bastion carried it out |
| The agent follows its request (`request <id> --wait 30s --json`) | State `stopped`, outcome "You stopped aider"; the process is gone |
| The agent asks to stop the next cron'd `aider`; the owner denies it (`deny --machine <id>`, no code) | Denied; the agent's `request` reads `denied` with exit status 1; `aider` keeps running |
| The agent asks the same stop again | Refused: the owner refused this same stop within the last 24 hours |
| `other` tries `approvals --machine`, `approve`, `deny`, `doctor` | Each refused, naming the owner's account, with the administrator's command as typed (`sudo -H privatae-bastion approve --machine <id>`); the request stays waiting |
| `other` reads `agents --json` | Told the machine's bastion answers only its owner, and shown what that account can read itself |
| `other` asks after the agent's request (`request <id>`) | `unknown`: no such request was asked from that account |
| The machine's audit log | Each ask, approval and denial names the asking account, the asking agent (Claude Code, remote login) and the target (aider, scheduled job); each act from the owner's account is its own line naming that account |

Found and fixed while running M1 on this machine, before this record:
`switch --list` was refused by the M0 guard meant for `switch`; a read the
bastion answered but could not build came back as a refusal with the
administrator's command; "not paired" named `pair` without `sudo -H`; an act
refused for another account said "reads" and gave a bare `deny`; and
`approve` and `approvals --machine` from another account were refused as a
read and without `--machine`.

## Transcript (abridged)

```
$ ~/.local/bin/claude -c 'privatae-bastion agents --json'      # summarised
  aider pid 5162 origin scheduler user tester
  claude-code pid 5265 origin remote user tester

$ ~/.local/bin/claude -c 'privatae-bastion stop 5162 --json'
{
  "request": "857285ef",
  "state": "waiting",
  "text": "Stop aider in /home/tester (pid 5162) on this machine, and every process it started. Asked from Claude Code (pid 5324), running as tester.",
  "asked_as": "tester"
}

$ privatae-bastion approvals --machine
[857285ef]  asked 2026-11-02T05:23:07Z
Stop aider in /home/tester (pid 5162) on this machine, and every process it started. Asked from Claude Code (pid 5324), running as tester.

$ privatae-bastion approve --machine 857285ef                      # a wrong code
Approve this? Enter the code from your authenticator (or leave empty to cancel): error: code refused
$ privatae-bastion approve --machine 857285ef
Approve this? Enter the code from your authenticator (or leave empty to cancel): approved.

$ ~/.local/bin/claude -c 'privatae-bastion request 857285ef --wait 30s --json'
{
  "request": "857285ef",
  "state": "stopped",
  "outcome": "You stopped aider (pid 5162) running on this machine.",
  ...
}

$ ~/.local/bin/claude -c 'privatae-bastion stop 6145 --json'      # the next cron'd aider
  "request": "f090208b", "state": "waiting"

other$ privatae-bastion approve --machine f090208b
error: this machine's bastion acts only for its owner's account (tester), not other
  As the administrator:  sudo -H privatae-bastion approve --machine f090208b
other$ privatae-bastion approvals --machine
error: this machine's bastion answers reads only for its owner's account (tester), not other
  As the administrator:  sudo -H privatae-bastion approvals --machine

$ privatae-bastion deny --machine f090208b
denied.
$ ~/.local/bin/claude -c 'privatae-bastion request f090208b --json'
  "state": "denied"                                                  (exit status 1)
$ ~/.local/bin/claude -c 'privatae-bastion stop 6145 --json'
  "why": "the machine's owner refused this same stop within the last 24 hours, so it cannot be asked again yet"

# the machine's audit log (machine-factor/audit.jsonl), summarised
05:23:07Z local_stop_ask  asked to stop aider (pid 5162)  asker: tester, claude-code, remote  target: aider, scheduler
05:23:08Z stepup_approve  approved: local_stop|5162|aider asker: tester, claude-code, remote  target: aider, scheduler
05:23:08Z owner_lane_act  approve the machine's request 857285ef…, from the owner's account tester through its ask socket
05:24:04Z local_stop_ask  asked to stop aider (pid 6145)  asker: tester, claude-code, remote  target: aider, scheduler
05:24:06Z stepup_deny     denied: local_stop|6145|aider   asker: tester, claude-code, remote  target: aider, scheduler
05:24:06Z owner_lane_act  deny the machine's request f090208b…, from the owner's account tester through its ask socket
```
