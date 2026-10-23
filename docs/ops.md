# Ops and action ops

## Ops: programs your host wrote, run in a sandbox first
A host can ship an op, a small program (`op.yaml` plus `run`) it wrote and
tested, identified by the sha256 of its contents. It runs here only under
terms the host signed and you approved: once, with these parameters, or as a
standing grant with parameter bounds, an expiry and a use count (never as
root). Every run is a dry run first, in a throwaway sandbox with no network,
an overlay over this machine's disks, and this bastion's own records masked;
it reports what the op would create, change and remove. An op sees only the
system's programs and libraries, a few `/etc` files that hold no secret, and
the paths its manifest declares (its effects and its `reads`). Every other
file and folder is covered with an empty one. A link is left in place, so an
op can read where a link points, but not what is there. The op can also see
the names of the folders it was denied, in its own mount table. A declared
path that reaches a credential store is refused, as written and as it
resolves, and checked again at every run. The stores are `/root`, `/etc/ssh`,
`/etc/shadow`, `/etc/wireguard`, `/etc/systemd`, docker's and k3s's keys and
more, plus any path you list in this machine's `sensitive_paths`. Covers are
put on paths, so a bind mount or a hard link that you make yourself, putting
a credential file inside a declared path, is seen through it. List such a
path in `sensitive_paths`. Anything outside the
op's declared file effects refuses the run. Applying is the same run again,
then a check in a fresh sandbox. A one-time apply is bound to the change list
the dry run showed you, and lands nothing else. A run under a standing grant
is bound to the grant's parameter bounds and the op's declared effects
instead: you approved the grant, not each run's change list. Linux only, and file effects only; other platforms refuse every op
and say so. `privatae-bastion ops` lists what is held, and `ops drop <grant>`
takes a standing grant back.

## Action ops: ship steps, run the same way
A ship step acts rather than edits: it builds and pushes an image, moves a
source tree to a new commit, restarts a service, rolls a workload. An op with
`kind: action` does this in two parts, and approving it works the same way:
a dry run first, then an apply bound to the change list the dry run showed.

- **The op's program runs unprivileged.** Each run gets a uid no earlier run
  had, in its own systemd transient unit, with no capabilities and no new
  privileges. This machine's files
  are read-only to it: it writes only to a private work folder at `/tmp` and
  its own throwaway `/run` and `/var/tmp`. It sees only what a files op sees
  (above).
- **Its network, in an apply,** reaches only the `destinations` it declares
  (`host:port`):
  - the unit's address allowlist holds it to the addresses those names
    resolved to when the run began;
  - Landlock holds its TCP connections to the declared ports, and blocks
    abstract unix sockets and signals outside the sandbox;
  - UDP is held to the declared addresses but not to their ports, and a port
    declared for one address is open on every declared address;
  - a destination on this machine, a link-local address, or a cloud's
    metadata service is refused, as written and as resolved.

  **A dry run has no network at all,** because nobody approved it.
- **Memory: no ceiling, and the op goes first.** A run may use whatever
  memory the machine has to spare. It is the first thing stopped when the
  machine runs short:
  - the kernel, if it must kill, kills the op before anything else;
  - the bastion stops the op when free memory falls to a floor. The floor is
    the largest of 1 GiB, 5% of memory, and, on a Kubernetes node, the
    kubelet's own eviction line (hard or soft) plus 512 MiB, so the op goes
    before any pod is evicted. A kubelet setting it cannot read raises the
    floor, never lowers it;
  - the bastion also stops the op when the machine's services, pods, users or
    another op running beside it start waiting on memory: 7 points more of the time than the least they
    had during the run. The op's own waits don't count, and neither does a group that was
    already waiting, such as a pod at its own limit;
  - a machine already under the floor starts no op;
  - a run counts as stopped only if the kill landed.

  The refusal says what happened and how much the op had used.
- **Credentials:** it is handed the `credentials` it declares, sealed by the
  host to this machine's encryption key and bound to that run, in its
  environment only. A credential a verb names goes to the verb, never to the
  program. They are scrubbed from its output and gone when the run ends. A
  dry run is handed none.
- **The builder:** an op that declares `builder` reaches this machine's
  builder socket in an apply, never in a dry run, and never through a
  privileged group.
- **Root work is done by this bastion, as named verbs** the manifest declares
  with their arguments written in:
  - `tree.checkout` moves an existing git tree forward to an exact commit from
    its own origin. It runs only in a tree root owns, whose `.git` no one
    else can write, and never writes into a folder another user controls. It
    never runs the tree's hooks, never overwrites an ignored file the machine
    keeps, and refuses a tree with local changes or a git config that could
    run a program.
  - `unit.reload` and `unit.restart` act on one systemd service, never the
    bastion's own.
  - `k8s.set_image` sets one container's image to a digest, only forward:
    - the digest needs a receipt this machine signed for an image one of its
      op runs reported, built from the repository the manifest names;
    - its commit must descend from the one behind the live image;
    - the live image's commit counts only if this machine rolled it. An
      image it did not roll is refused, and the refusal says so.
  - `logs.check` returns a verdict and one line, read after the apply.

  Only a commit and a digest may come from the run's parameters. The program
  cannot ask for a verb. An op with verbs is root, so it is never a standing
  grant.

What a program pushed becomes a receipt, signed by this machine. The
heartbeat says whether this machine can run action ops (`action_ops`) and
carries its encryption key, signed by the machine's own key. A run that
this bastion's restart cut short leaves nothing: the next start unmounts
its files and stops its unit.
