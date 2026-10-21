# Approvals

## Approvals with a local second factor
`stepup-enroll` enrols an authenticator on this machine. From then on a
request to install a folder grant, apply a move plan, pull a model, or open a
root session shows up under `privatae-bastion approvals` in plain words, and
you `approve` or `deny` it here with a code the host never handles. Without an
enrolled factor, folder grants and move plans are gated by the signed grant
alone and the host verifies its own factor; model pulls and root sessions are
refused outright.

## Writes on an anchored machine wait for your approval
On a machine anchored to a host, every management op is either a read or a
write. Reads answer on the anchor host's word. A write (a model drop, a
terminal, a job, a self-update, stopping a process, running a local tool to
extract a document)
runs only on an approval that this machine verifies and spends: bound to that
op, this machine and a digest of exactly its arguments, single use. You give
it either with the second factor enrolled here or from your **approval
device**: `device-init` makes one machine of yours the device, and
`pin-device <key>` on each machine you govern accepts what it signs. The
device shows each ask in the machine's own words and signs only that; a root
terminal still needs the code at the machine itself. Six kinds of write
take no fresh approval: standing work under a place you set up at the machine
(the nightly backup fetch, the host's context store), a run under op terms you
already approved (see [Ops](ops.md)), a root command under the root-command grant
you gave at this machine with the code (see [Session lane](lanes.md#session-lane)), the anchor
host's signed record of who else
may pair here, taking something away (a revoke), and a self-update to a newer
version we signed (see [Heartbeat and self-update](updates.md)). A local, unanchored machine is unchanged: the pairing is
the authorization on your own computer.

The lane watches itself: five refused writes from one pairing within ten
minutes close that pairing's write lanes on this machine for ten minutes,
doubling on repeat. Reads and revokes are never held. `quarantine clear
<host>` lifts it.

## Approvals from the taskbar
On the machine that is your approval device (`device-init`), every ask a host
files for one of your machines raises a notification on Windows. Clicking it, or the
tray's approvals line, opens the approvals window: each ask in plain words,
with Approve and Deny, and "Approve all shown" when there are several. Approve
signs with this device's key exactly as `device-approve` does: one run, on the
machine the ask names, within the hour. "Approve all" signs only the asks the
window showed you, never one that arrived after. The same window lists the
requests waiting for a code on this machine itself. The window does not
redraw by itself while you read it: when something new arrives it says so and
waits for you to show it. Off Windows the window is a page of the local
console (`privatae-bastion ui`, then Approvals in the header).
