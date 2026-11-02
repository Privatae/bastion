# Status: what works today, and what does not

Kept by hand; each line says where it was checked. "Run" means on a real,
fresh machine. "Tested" means the tests in `client-go`, which CI runs on Linux.
"Built" means it compiles and passes `go vet` for that system, and the logic
it shares with Linux is tested there, but it has not run on that system yet.

## On its own, with no Host

| | Linux | macOS | Windows |
|---|---|---|---|
| Install for the whole machine from your own account | run ([gate](verification/m0-gate-linux-2026-10-31.md)) | built | not run |
| `--just-me`, and the fall back where sudo cannot be used | run | built | not run |
| Moving from an install for your account to one for the whole machine keeps its pairings | not needed (one state folder) | not built | built |
| An update restarts the bastion | run | built | built (the service restarts it; a sign-in task's copy waits for the old one to exit) |
| Every AI agent, by its program or its connection to a model | run | built | built |
| Who started each one (terminal, remote login, schedule, service, another agent) | run | built | built |
| Claude Code: session title, permission mode, what it is running now | tested | read, not checked against the process's start time | read, not checked against the process's start time |
| An agent's folder, git branch and start time | run | not read yet | not read yet |
| Scheduled jobs that start an agent | run (cron) | built (launchd) | built (Task Scheduler) |
| MCP tool servers and their problems | tested | built | built |
| Changes since your baseline | tested | built | built |
| Stop an agent with your code, from the console or `stop` | run | built | built |
| An agent on the machine asks to stop another, and follows the answer | run ([gate](verification/m1-gate-linux-2026-11-02.md)) | built | built (the ask pipe) |
| An agent reads the machine: `agents`, `agents show`, `activity`, `doctor`, the `--json` reads | run | built | built (the ask pipe) |
| The owner answers from their own account: `approve`, `deny`, `switch`, the drops | run | built | built (the ask pipe) |
| The installer checks the release's signature | tested | built | not built (`install.ps1` checks the digest only) |
| The console from the owner's own account, no sudo or Administrator terminal | run | built | built (the ask pipe); the tray's approvals window |
| Activity, report | run | built | built |
| `uninstall`, keeping the audit log | run | built | built |
| A notice when something is waiting | none yet | none yet | the tray |

## Not detected yet

GitHub Copilot, Cursor's editor (Cursor's command-line agent is detected) and
Windsurf: the bastion has no signature for them ([`agents.go`](../client-go/agents.go)).
Session titles are read for Claude Code only; Codex, opencode, Gemini CLI,
aider and goose sessions show their program, folder and tool servers.

## With a Host

Everything in the README's [Works with a Host](../README.md#works-with-a-host):
folders, models, terminals, ops, ship plans, backups, the memory mirror, coder
runs and the service slot. Those are tested here and have run with Privatae's
own Hosts; this file does not track them line by line.

Not built: pairing over the internet to a control plane you run yourself, and
a relay image for one behind a home router.

## Known problems

- The bastion agent (folder search, a separate program) keeps the plain text it
  extracts from a shared folder's files in `<folder>/.agent`, inside the shared
  folder, where a sync client can copy it, and two grants over the same
  folder (from two Hosts, say) share that one `.agent`. The bastion never
  serves that folder. The fix moves it under the bastion's own state, per
  pairing and store.
- There is no MCP endpoint on the bastion, on purpose. An agent on the machine
  uses the command line ([for agents](skills/bastion.md)).
