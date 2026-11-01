# Command reference

| Command | What it does |
|---|---|
| `pair <token>` | Enrol this machine with a host. Each pair adds a host; re-pairing an existing host is refused. |
| `pair -` | The same, with the token as the first line of standard input, so it is not in the process list or your shell history. Only `-` reads standard input: `pair` with no token is the usage error. Every form of `pair` takes `-` in place of `<token>`. |
| `pair --replace <token>` | Re-pair an existing host: rotates its credentials, keeps its port, context store and DCN state. |
| `pair [--replace] --redeem-url unix:///<socket> <token>` | Pair with a Host on this machine over its enroll socket. Its CA is pinned for life. See [A Host on this machine](host-on-this-machine.md). |
| `pair [--replace] --redeem-url https://<host>:<port>/<path> --host-ca <pem> <token>` | Pair with a Host in a VM on this machine over its enroll port, trusting that CA alone. Its CA is pinned for life. See [A Host in a VM on this machine](host-on-this-machine.md#a-host-in-a-vm-on-this-machine). |
| `pair <pairing code>` | Pair with the one code (`skp_…`) a Cloud Host's "Set up a bastion" card gives: it carries the enroll address and the fingerprint of the Host's CA, and the CA is taken from the enroll port only under that fingerprint. On a local machine that already serves a Host it asks, on this machine's terminal, whether to add this one; only a yes adds it. |
| | The card's one line installs the bastion, pairs it with that code and starts it: `curl -fsSL https://privatae.ai/bastion/install.sh \| PRIVATAE_PAIR_CODE='skp_…' sh` on macOS and Linux (the code goes in the environment, never in an argument, which the process list would show), and `& ([scriptblock]::Create((irm https://privatae.ai/bastion/install.ps1))) -Pair 'skp_…'` on Windows. Either hands the code to `pair -` on standard input. |
| | `pair` exits 0 when it paired, 3 when this machine is already paired with that Host (nothing changed), and anything else on a failure. |
| `run` | Start the bastion: it watches this machine whether or not a Host is paired, and brings up the tunnel and lanes for every paired host. A Host paired later is started without a restart. |
| `status [--json]` | Show every pairing and its tunnel status, or, with no Host paired, whether the bastion is running on its own. From the owner's account beside the bastion installed for the whole machine, it reads that bastion (see [Reads from the owner's account](#reads-from-the-owners-account)); when nothing answers, it says the service is not answering. |
| `ui` | Open the local console in your browser. Installed for the whole machine, it opens for the administrator (`sudo -H`) and, on Linux and macOS, as a limited session for the machine's owner account ([console](console.md)). |
| `uninstall [--delete-data]` | Remove the service and the program from the installers' places. The state stays (pairings, keys, the audit log) unless `--delete-data`, confirmed by typing `delete` at a terminal. Installed for the whole machine it needs the administrator; from another account it removes that account's own bastion only. |
| `add-folder [--host <host>] <path> [name]` | Add a folder to your network. `--host` is required when more than one host is paired. |
| `context` | Choose what your files become on your network. Runs as you. |
| `stepup-enroll [--host <host> \| --machine] [--rotate]` | Enrol (or rotate) a second factor on this machine: a Host's (`--host`), or your own as the machine's owner (`--machine`, and the default when no Host is paired). The owner's factor approves what is asked of the machine itself rather than by a Host. |
| `approvals [--host <host> \| --machine] [--json]` | List what is waiting for your approval here, in plain words: a Host's requests, or with `--machine` what is asked of the machine itself. |
| `approve [--host <host> \| --machine] <id>` / `deny …` | Answer one request with a code from the matching authenticator enrolled here. A Host's code never approves what is asked of the machine, nor the other way round. |
| `approvals drop [--host <host> \| --machine] <id>` | Take back an approval this machine issued and has not used yet. |
| `grants drop <store id> [--host <host>]` | Remove a folder grant held on this machine. The host is told. |
| `device-init` | Make this machine your approval device. |
| `device-approvals` | What your machines are asking you to approve, in their words. |
| `device-approve <id>\|all [--code <code>]` / `device-deny <id>` | Approve or refuse from the device. `all` signs only the asks the last listing showed, and never a ship plan that runs root work: that takes `--code`. |
| `pin-device <key>` / `unpin-device <key>` | On a machine you govern: accept (or stop accepting) approvals signed by your device. Root required. Prints the `pin-machine` line to run on the device. |
| `pin-machine <host> <key>` / `unpin-machine <host>` | On your device: pin (or drop) a machine's key, as that machine printed it, so the device can sign ship plans that include it. |
| `ops [--host <host>]` | The ops your host wrote that this machine holds, and the standing op grants. |
| `ops drop <grant> [--host <host>]` | Take back a standing op grant. The host is told. |
| `coders set [--max N] [--mem MB] [--cpus F] [--engines a,b\|all] [--allow-lan host[:port],...] [--image-prefix <registry/path/>\|default]` | Size this machine for coding runs your hosts place here: how many at once, memory and CPUs per run, which engines, LAN hosts a run may reach, and where run images may come from (`<prefix>harness-<engine>@sha256:...`; default `git.privatae.ai/privatae-harness/`). Does not switch them on. |
| `coders on` / `coders off` | Allow coding runs here (Linux, bastion running as root), filling unset sizes with defaults; or stop new ones. Off by default. Each run is a container with no network of its own. Through this bastion it reaches the public internet, and never this machine or its LAN unless you named that host with `--allow-lan`. |
| `coders drop [--host <host>]` | Take back the standing coder grant of every host, or one, and stop their runs. |
| `coders status [--json]` | The coder settings, grants and runs on this machine. |
| `quarantine clear <host>` | Reopen a host's write lanes that this machine closed after repeated refusals. |
| `quarantine clear --asker <account>` | Let agents running as that account ask this machine again. Five refused asks from one account within ten minutes (the owner denied them, or they were refused: not an agent, refused in the last day, too many waiting) hold its asks for ten minutes, doubling on repeats and forgiven after a clean day. The holds are kept beside the owner's code, never sent to a Host. |
| `git-setup` | Print the `git config` lines that route `git.privatae.ai` through this bastion. |
| `git-credential` | Git credential helper. Fetches your forge token from your host on every auth. |
| `unpair <host>` | Tear down one pairing. Context store and DCN state are left in place. |
| `set-mode <local\|networked>` | Switch modes. `networked` needs root; `local` is refused while several hosts are paired or the machine is anchored. |
| `service install\|uninstall\|status` | On macOS and Windows, run the bastion as the system's own service. `install` and `uninstall` need machine authority. |
| `claim-anchor [--owner <name>] [--host <host>] [<token>]` | Networked mode: make a host the anchor. No token when the host is already paired here. Also `--rotate <token>`, `--repin`. Root required. |
| `release-anchor --host <host> (--host-ca <pem> \| --force)` | Let go of an anchor whose Host is gone: unpair it and set its state aside, so a new Host can be anchored. `--host-ca` is the new Host's CA. Root required. |
| `claim-owner <name>` | State who owns this machine. Root required. Optional; grants nothing. |
| `root-exec grant [--host <host>] --for <duration>` / `root-exec revoke` | Let the anchor host run commands as root here, with the code from the authenticator enrolled here, until a time you choose (30 days at most); or take it back. `root-exec` alone shows the grant held. Granting needs root. |
| `report [--since 7d] [--json] [--out FILE \| --out -]` | Write what this bastion knows as one Markdown file (or JSON): a summary of the problems first, then the agents running now, scheduled jobs that start an agent, MCP tool servers and their problems, changes since the baseline, and the activity in the period. No AI model writes any of it; last prompts and secrets are left out. Default file: `reports/` in the config directory of the account that ran it; `--out -` prints it instead. |
| `activity [--since 7d] [--json]` | What happened on this machine, newest first: stops (by you or a Host, and stops refused), your approvals, what each Host did here, Hosts paired or removed, programs marked as yours, capabilities switched off. Read from the records this bastion already keeps. |
| `agents [--json] [--prompts]` | Every AI agent on this machine and what it is doing: for Claude Code, the session's name and title, whether it is waiting for you and on what, and its permission mode, read from Claude Code's own session files; for every agent, its folder and git branch, how long it has run, who started it, what it is running now (secrets redacted) and the tool servers it started with itself. Names and titles are what each agent says about itself. `--prompts` adds each session's last prompt. Nothing here is sent to a Host. |
| `stop <session name or pid> [--wait 5m] [--json]` | Stop an agent this bastion sees, and every process it started, as the machine's owner. At a terminal it asks for your code (`stepup-enroll --machine`); run by an agent, it only files a request that you approve under Waiting for you in the console (or with `approve --machine`). `--wait` follows the request until it is answered, as `request` does. When the bastion is installed for the whole machine and the command runs in another account, it asks over the bastion's local ask socket, which names the asking account (and on Linux the asking agent) from the kernel; one account may have five requests waiting. The running bastion carries it out within two minutes of the approval or not at all, and never stops an app you are using, the bastion itself, or a process the scan does not see as an agent. |
| `request <id> [--wait 5m] [--json]` | Where an ask stands, for the account that asked it: `waiting`, `approved` (being carried out), `stopped`, `not_stopped` (with the reason), `denied`, or `unknown` (no such ask from this account, or older than a day). Exit status 0 for stopped, 1 for not, 3 when still waiting after `--wait`. Another account's requests read as unknown. Every ask, approval, denial and stop is recorded with the asking account, the asking agent and the target, each with how it was started. |
| `help` | Print every command. |
| `switch <host> <family> on\|off` / `switch --list` / `switch --reset` | Switch a capability family off for one host on this machine, or back on; `--list` shows every host's families. If the list of switched-off families cannot be read, every family is refused to every host until `--reset` sets the unreadable file aside (kept, not deleted). Switching and resetting need root. |
| `approvals-owner --sid <SID> [--replace]` | Windows, beside the system service: name the one account whose tray icon may list and answer approvals. Administrator only. |
| `approvals-owner --account <name> [--replace]` | Linux and macOS, beside the system service: name the machine's owner account, whose `ui` opens a limited console session without sudo. The installer records the account that ran it through sudo. Another account takes it over only with `--replace`, typed at a terminal. Administrator only. |
| `tray` | Windows, beside the system service: your icon and approvals window, started at every sign-in. |
| `observe` | Print the agent, automation and scheduler snapshot the next check-in would carry. |
| `schedules [--json]` | Scheduled jobs that start an AI agent with nobody at the keyboard: cron and the other schedulers this platform has, with the schedule in words, the account and the command (secrets redacted). |
| `tool-servers [--json]` | The MCP tool servers in every settings file this bastion can read, by the agent or app they belong to, and what is wrong with each: a key written in plain text, a package with no fixed version, a server running that no settings file names. |
| `posture [--json]` | Linux: the checks a Host runs on its own servers, in words: ufw, the pubwall nftables table, iptables' INPUT policy, whether SSH is open to any address, fail2ban, waiting security updates (apt), a restart needed, disk use, load and the system log. The firewall checks need the administrator, or the owner's account through the bastion installed for the whole machine. |
| `baseline record [--force]` | Record what is normal on this machine. Administrator only; `--force` replaces the baseline held. |
| `baseline [show] [--json]` | Print the baseline this machine holds. |
| `baseline diff [--json]` | What is running that the baseline does not hold. Administrator only, or the owner's account through the bastion installed for the whole machine. |
| `observe:baseline [--force]`, `observe:baseline:show`, `observe:delta [--json]` | The same as `baseline record`, `baseline show` and `baseline diff`, under their old names. |
| `backup key init [--replace] [--label <name>]` | Make this bastion's backup key and print the fields to register on your host. `--replace` keeps the old key. |
| `backup key show` | The backup key this bastion holds, and the older ones it keeps. |
| `backup requests [--host <host>]` | Restore requests your host sent this machine. |
| `backup approve [--host <host>] <id>` / `backup deny …` | Answer one: approving seals that one backup's key to the requesting host. |
| `backup reseal --sidecar <file> --to <host key>` | Seal one backup's key to a host's own key, offline. |
| `backup restore-plan --dir <folder> [--stamp <stamp> --to <host key>]` | List the backups in a folder; reseal one for the host that replaces a lost one. |
| `backup share --with <host> (--from <host> \| --dir <folder>)` | Let a paired host list and ask for the backups in another host's folder (or any folder). |
| `backup shares --with <host>` / `backup unshare --with <host> <name>` | The folders shared with a host; take one back. |
| `version` | Print the version. |

Run `privatae-bastion` with no arguments for the built-in help.

## Reads from the owner's account

Installed for the whole machine, the bastion runs as root and keeps its records in root's state. On Linux and macOS, the account recorded as the machine's owner (`approvals-owner --account`, which the installer writes) reads them without sudo: `status`, `agents`, `schedules`, `tool-servers`, `posture`, `baseline show`, `baseline diff`, `activity`, `report` and `approvals` ask the running bastion over its local ask socket, which knows from the kernel which account is asking, and print what it answers. That is what the console already shows the owner, so an agent the owner runs can read it too; `posture`, which the console has no page for, adds the firewall checks, read by the bastion as the administrator. No read prints the delegation tag an agent carries, as the console never shows one. Nothing that changes anything goes this way; those still take the owner's code.

Any other account is refused. `agents`, `schedules`, `tool-servers` and `posture` then show what that account can read itself, and say so; the rest print the refusal and the administrator's command. Comparing against the baseline, the posture checks and the report are reused for 30 seconds, and the bastion answers four reads at a time, so a polling agent cannot slow the machine.
