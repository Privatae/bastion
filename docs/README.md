# Bastion reference

The front page is the [README](../README.md). These pages hold the reference
text, one topic per file.

## What the bastion does

Everything below is in `client-go/` and compiled into the one binary.

- [lanes.md](lanes.md): the scoped WireGuard tunnel, the git lane, the worker lanes, and the session lane with terminals and root commands.
- [context.md](context.md): your files turned into text on this machine, and the DCN stores a host reads through signed grants.
- [models.md](models.md): the model store ops (`model:list`, `model:pull`, `model:drop`) and when the ollama forward is filtered.
- [approvals.md](approvals.md): approvals with a local second factor, writes on an anchored machine, and the approvals window.
- [ops.md](ops.md): programs a host wrote, run in a sandbox first, and action ops for ship steps.
- [ship-plans.md](ship-plans.md): one signed plan for a ship across several machines, its receipts and its undo.
- [service-slot.md](service-slot.md): a server a host built, running here with no network.
- [observe.md](observe.md): what is running on this machine, as read-only observe ops.
- [updates.md](updates.md): the heartbeat and the signed self-update.
- [memory-mirror.md](memory-mirror.md): a streaming replica of a host's database on your hardware.
- [backups.md](backups.md): this bastion's backup key, restore requests, backups kept here, and restoring a lost host.
- [audit.md](audit.md): the audit files on this machine and the same rows in its system log.
- [console.md](console.md): the local console.
- [host-on-this-machine.md](host-on-this-machine.md): pairing with a Host on the same machine over unix sockets, or in a VM over forwarded ports.

## Using and checking it

- [install.md](install.md): how the system service runs on Linux, macOS and Windows, and where release binaries and the signed manifest are served from.
- [commands.md](commands.md): every command and what it does.
- [security-model.md](security-model.md): the security model, every point in full.
- [claims.md](claims.md): for each security claim, the test that fails if it stops being true, or a note that there is none.
- [build.md](build.md): cross-compiling, running the tests, and running the fuzz targets.
- [layout.md](layout.md): the repository layout, and the names that keep the word freeagent.
