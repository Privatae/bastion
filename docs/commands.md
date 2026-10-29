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
| `run` | Bring up the tunnel and lanes for every paired host. |
| `status` | Show every pairing and its tunnel status. |
| `ui` | Open the local console in your browser. |
| `add-folder [--host <host>] <path> [name]` | Add a folder to your network. `--host` is required when more than one host is paired. |
| `context` | Choose what your files become on your network. Runs as you. |
| `stepup-enroll [--host <host>] [--rotate]` | Enrol (or rotate) the second factor on this machine. |
| `approvals [--host <host>]` | List what your host is asking to do here, in plain words. |
| `approve [--host <host>] <id>` / `deny …` | Answer one request with a code from the authenticator enrolled here. |
| `approvals drop [--host <host>] <id>` | Take back an approval this machine issued and has not used yet. |
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
| `git-setup` | Print the `git config` lines that route `git.privatae.ai` through this bastion. |
| `git-credential` | Git credential helper. Fetches your forge token from your host on every auth. |
| `unpair <host>` | Tear down one pairing. Context store and DCN state are left in place. |
| `set-mode <local\|networked>` | Switch modes. `networked` needs root; `local` is refused while several hosts are paired or the machine is anchored. |
| `service install\|uninstall\|status` | On macOS and Windows, run the bastion as the system's own service. `install` and `uninstall` need machine authority. |
| `claim-anchor [--owner <name>] [--host <host>] [<token>]` | Networked mode: make a host the anchor. No token when the host is already paired here. Also `--rotate <token>`, `--repin`. Root required. |
| `release-anchor --host <host> (--host-ca <pem> \| --force)` | Let go of an anchor whose Host is gone: unpair it and set its state aside, so a new Host can be anchored. `--host-ca` is the new Host's CA. Root required. |
| `claim-owner <name>` | State who owns this machine. Root required. Optional; grants nothing. |
| `root-exec grant [--host <host>] --for <duration>` / `root-exec revoke` | Let the anchor host run commands as root here, with the code from the authenticator enrolled here, until a time you choose (30 days at most); or take it back. `root-exec` alone shows the grant held. Granting needs root. |
| `switch <host> <family> on\|off` / `switch --list` | Switch a capability family off for one host on this machine, or back on; `--list` shows every host's families. Switching needs root. |
| `approvals-owner --sid <SID> [--replace]` | Windows, beside the system service: name the one account whose tray icon may list and answer approvals. Administrator only. |
| `tray` | Windows, beside the system service: your icon and approvals window, started at every sign-in. |
| `observe` | Print the agent, automation and scheduler snapshot the next check-in would carry. |
| `observe:baseline [--force]` | Record what is normal on this machine. Administrator only. |
| `observe:baseline:show` | Print the baseline this machine holds. |
| `observe:delta [--json]` | What is running that the baseline does not hold. Administrator only. |
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
