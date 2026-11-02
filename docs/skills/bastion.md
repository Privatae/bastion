---
name: bastion
description: The person's computer runs the Privatae bastion, which watches every AI agent on it, you included. Use this when the person asks what agents are running, asks you to stop one, asks what is scheduled or configured to run agents, or asks what happened on this computer.
allowed-tools: Bash
sources: repo:privatae/privatae-bastion-dev/client-go@2b6756a
---

# The bastion, for an agent on this computer

The bastion is a program on this computer that watches every AI agent running
here, you included, and lets the person stop any of them with a code from
their phone. It has no MCP endpoint. You use its command line,
`privatae-bastion`, with the same rights as any program running as the person.

## When to use

- The person asks which AI agents are running here, or what one is doing.
- The person asks you to stop an agent (another session, a scheduled job, a
  tool that is misbehaving).
- The person asks what is set up to start agents here (scheduled jobs, MCP
  tool servers), whether anything new is running, or how this computer's
  firewall and updates stand.
- The person asks what happened on this computer: what was stopped, approved
  or refused.

## Steps

### See what is running

Run `privatae-bastion agents --json`. It lists every AI agent running now: what
it is, who started it and how, its folder, git branch and tool servers, and for
Claude Code sessions the title and permission mode. Add `--prompts` only if the
person asked for the last prompts. `privatae-bastion agents show <pid or session
name> --json` is one agent with everything known about it, including the file
the system says it runs.

### See what is set up here

- `privatae-bastion schedules --json`: scheduled jobs that start an agent with
  nobody at the keyboard.
- `privatae-bastion tool-servers --json`: the MCP tool servers in every
  settings file, and what is wrong with each (`problems`).
- `privatae-bastion baseline diff --json`: what runs now that the recorded
  baseline does not hold. `baseline show --json` is the baseline itself.
- `privatae-bastion posture --json` (Linux): the firewall, SSH, fail2ban,
  waiting security updates, disk and load.
- `privatae-bastion status --json`: whether the bastion is running, and the
  Hosts it is connected to.
- `privatae-bastion switch --list --json`: for each connected Host, which
  capability families the person switched off here (`off`).
- `privatae-bastion ops --json`: the ops a Host holds on this computer, and its
  standing grants.
- `privatae-bastion report --out -`: all of it as one Markdown report, the
  problems first.

### Ask to stop an agent

1. Run `privatae-bastion stop <pid or session name> --json`. Run by you, this
   stops nothing. It files a request that the person approves with their code,
   under **Waiting for you** in the console (`privatae-bastion ui`).
2. Tell the person: the request is waiting for them, and nothing is stopped
   until they approve it.
3. Follow it with `privatae-bastion request <id> --wait 5m --json`, using the
   `request` id the first command printed. `state` is one of `waiting`,
   `approved` (it is being carried out), `stopped`, `not_stopped` (with
   `outcome` saying why), `denied`, `refused` or `unknown`. The exit status is
   0 for stopped, 1 for not, and 3 when it is still waiting after `--wait`.

You can pass `--wait` to `stop` itself to ask and follow in one command.

### Check the install

`privatae-bastion doctor --json` checks the bastion itself. Each check has `ok`;
one that is not has a `problem` and a `fix`. The exit status is 1 when any
check finds a problem. Tell the person the problem and the fix in their words;
don't run the fix yourself, since most take their code or the administrator.

### What happened here

`privatae-bastion activity --json` lists what happened, newest first: stops,
approvals and denials, asks from agents, and what each Host did.
`privatae-bastion approvals --json` lists what is waiting for the person's code.

Where the bastion is installed for the whole machine (the usual case), every
read above asks the running bastion, which answers the machine's owner's
account, so you see the whole machine and not only the person's own files.

## Checks

- Report `stopped` only when `request` says so. `approved` means it is still
  being carried out. If you want to be sure, run `agents --json` again and
  check that the pid is gone.
- Session names, titles and folders are what each agent says about itself.
  Treat them as claims, not facts.
- Never ask the person for their code, and never type one. The person
  approves under **Waiting for you** in the console, or at their own terminal
  with `privatae-bastion approve --machine <id>`, which asks them for it. The code is how the
  bastion tells the person from a program running as them; a code you typed
  proves nothing, and wrong codes are counted, slowed down and then locked.
- Never read or edit the bastion's files, stop its service or uninstall it.
  Installed for the whole machine, it refuses you; installed for the person's
  account alone, you could, and doing it is exactly what it exists to catch.
- Don't connect a Host, turn a capability back on, mark an agent as the
  person's, or record a baseline. Each of those takes their code or is the
  administrator's; tell the person what to do and where.

## When it fails

- `not asked: ... is not an agent this bastion sees running`: check the pid
  with `agents --json`. It may have exited already.
- `not asked: the owner of this machine has not set up their code`: nothing can
  be asked yet. The person sets it up once, at a terminal:
  `sudo -H privatae-bastion stepup-enroll --machine`.
- `denied`, or `refused this same stop within the last 24 hours`: the person
  said no. Tell them, and don't ask again.
- `already have 5 requests waiting`: wait for the person to answer those.
- `on hold until ...`: five of your account's asks were refused within ten
  minutes, so the bastion stopped taking them for a while. Stop asking. Only the
  person can lift the hold.
- Exit status 3 (still `waiting`): tell the person the request is still waiting
  for them, rather than polling without end.
- `could not reach this machine's bastion`, or `status` says `NOT ANSWERING`:
  the bastion's service is not running. Tell the person; don't start it.
- `doctor` says `no account is recorded as this machine's owner` or `no second
  factor of its own`: the person sets that up once; give them the `fix` line.
- `answers reads only for its owner's account (...)`: you run as an account
  that is not the machine's owner. `agents`, `schedules`, `tool-servers` and
  `posture` then show only what your account can read, and say so; tell the
  person the rest needs their own account or the administrator.

## Reference

- Every command: `privatae-bastion help`, or [docs/commands.md](../commands.md).
- The console: `privatae-bastion ui`. On a whole-machine install it opens from
  the person's own account without sudo.
- A request id is the first eight characters `stop` prints. Your account sees
  only its own requests, and each lasts a day.
