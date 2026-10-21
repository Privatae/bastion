# Ship plans: one approval for a whole ship

A ship is several action ops on several machines, in order: build and push
on one, move a tree and restart on another, roll a workload on a third. Your
device signs **one plan** listing every step, and each machine runs only its
own lines of it.

**What your device signs:**
- the pipeline, a version that only goes up, the commit being shipped, a
  nonce, and an expiry of at most four hours;
- each step: its machine, its op and that op's sha256, its params, the verbs
  it will run, the params it takes from an earlier step's receipt, and whether
  it may be undone;
- the key of every machine in it. The device fills these in from its own pins
  (`pin-machine`), never from your host. When you pin your device on a
  machine, the machine prints the exact `pin-machine` line to run on the
  device.

**Before signing, the device:**
- refuses a plan naming a machine it has not pinned;
- asks for your code when a plan runs root work, checks it against the
  factor enrolled on the device's own pairing (never one the ask names), and
  says in the plan that it did;
- keeps such a plan out of "approve all shown";
- shows every field as plain text: a plan whose params, inputs or verbs hold a
  control character, a line break or a Unicode direction mark is refused, so
  nothing in it can redraw or hide what you read.

**Each machine, before it runs a line, checks that:**
- the plan is signed by a device pinned there;
- it has not expired, and it is not older than a plan it already ran for that
  pipeline;
- it names this machine's own key for this machine;
- the line is for this machine, and has run fewer times than the plan
  allows (once, unless you approved retries). Its attempts run one at a
  time: the next only after the last one failed, never after one passed, and
  never after the step was undone. The machine keeps this record itself, and
  an attempt the bastion died in counts as failed. A tree or workload
  something else moved since the line's changes were read — while its
  program ran, or between two attempts — is left alone: the verb refuses
  it, so an undo can never take that other change back. Changes this
  bastion makes to one tree or workload, forward or undo, take turns;
  a change from outside is caught one command before the write;
- every line before it succeeded, shown by their signed receipts, so a check
  never runs before the step it checks;
- a root line comes with your code;
- the op it holds declares exactly the verbs the line showed you.

**Values that don't exist when you approve,** like the digest a build
produces, come from receipts. Each line ends in a receipt signed with the key
your device pinned for that machine, and the machine keeps it for your host
to read back (`op_plan_status`). A roll takes its digest only from a
successful earlier step of the same plan, at the plan's commit: the image the
plan's own build step reported, never one from another run. That rests on the
build op reporting truly, and that op is one you approved in the plan. The first roll on a machine with no
record of its live image says so on the device, and takes that image as its
starting point.

**Undo.** A step marked undoable is taken back once, to the state that
machine recorded before the step's first attempt. The machine records each
change before it makes it, so a retry, or a change the bastion died in the
middle of, is taken back too. An undo takes one of two signed receipts:
- a later step of the same plan failed its check (its apply ran, its verify
  or log check did not pass) on the last attempt the plan allows it, so no
  retry of it can still pass;
- the step's own latest attempt failed, and none of its attempts passed.

The tree or image goes back first; a unit the step restarted is restarted
after, on what was put back. A tree or workload that moved since is left
alone, and a file the machine keeps is never overwritten. Once undone, the
step never runs again.
