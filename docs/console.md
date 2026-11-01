# Local console

`privatae-bastion ui` opens a page served by the running daemon on `127.0.0.1`
and reachable from nowhere else. It works with no Host connected.

**Who it opens for.** The account the bastion runs as signs in with that
account's own key: on an install for one account, that account; installed
for the whole machine, the machine's administrator (`sudo -H privatae-bastion
ui`). On Linux and macOS the whole-machine bastion also opens for one more
account, the machine's owner, recorded by the installer on your own computer
(the account that ran it through sudo; never on a shared machine) or by hand
with `sudo -H privatae-bastion approvals-owner --account <name>`. Run there, `ui` asks the bastion over its local socket,
which learns the asking account from the kernel, and gets a one-use link to a
**limited** session ([`consolelane.go`](../client-go/consolelane.go)). Any
other account is refused. A limited session shows everything and does
everything that takes your code or only narrows reach. What widens reach and
takes no code stays with the administrator, and the page shows their command
in its place: connecting a Host, setting up or replacing your code, choosing
the Host in charge, proposing a folder or checking a path, approving the
approval device's requests, and the disk map, which, read as root, names files
in every account's home. One account may have 16 links waiting to be opened. A Host's requests can be answered there with that Host's code, and
wrong codes are throttled there as yours are.

- **Agents** (the home page): every AI agent running here and what it is
  doing. For Claude Code, the session's name and title, whether it is
  waiting for you and on what, and its permission mode, read from Claude
  Code's own session files; for every agent, its folder and git branch, how
  long it has run, who started it, what it is running now, and the tool
  servers it started. Flags: permission prompts off, not marked as yours, the
  stopping rule would stop it. Until your code is set up and a baseline is
  recorded, the page starts with the steps to do that. Each agent has its own
  page: its MCP tool servers and their problems, whether it is yours, the
  stopping rule's verdict, how the bastion knows what it is, **Stop this
  session** and **This one is mine**.
- **Waiting for you**: what is asked of this machine (a stop another agent
  asked for, with who asked) and what your Hosts ask, each answered with a
  code. Deny needs no code.
- **Activity**: what happened here, newest first: stops, your approvals, what
  each Host did, Hosts connected or removed, marks, capabilities switched off.
- **This machine**: the bastion's state and the Hosts it serves; scheduled
  jobs that start an agent; MCP tool servers on this machine and their
  problems; changes since your baseline (compare, or record a new one);
  **Write report**, one Markdown file with no model in it; what this machine
  has given away (where you switch a Host's capabilities off); the disk map.
- **Settings**: your code (an authenticator app, set up with a QR), the Hosts
  connected and what each may do, connecting one, the Host in charge on a
  shared machine, and the owner name.

**Your code.** Stopping an agent, marking one as yours, answering what is
asked of this machine, recording a baseline, releasing a Host from
quarantine and setting the owner name take a code from your authenticator,
typed on the page: anything that can drive your browser can press a button,
and cannot read your phone. Taking access away (disconnecting a Host,
switching a capability off, denying) needs no code. The code only keeps
agents out when the bastion is installed for the whole machine: installed in
your own account, an agent running as you can read the secret behind it, and
the console says so on every page.

On Windows a tray icon shows a one-line state. Run as you, it opens what is
waiting for your approval, the console and your context page, and can stop
the bastion. Beside the system service it opens approvals only.
