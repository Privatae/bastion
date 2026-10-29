# Backups

## Backups: this bastion's key, and a host's restore
Your host encrypts each of its backups before the backup leaves it, to the
host's recovery key (which you keep) and to every bastion key you registered
with it. The platform holds none of those keys. This bastion can hold one:
`privatae-bastion backup key init` makes it here and prints the three fields
to register on your host (kind `bastion`, a label, and the public key). The
key is a standard age key file, 0600, in the bastion's own state folder; only
its public half ever leaves this machine. `backup key init --replace` makes a
new one and keeps the old one beside it, because the backups made before
still need it.

Each backup also carries its own key, sealed in a small sidecar file next to
it to the same keys. When a host restores a backup, it asks this
bastion for that one backup's key (`backup_reseal`). Nothing is opened until
you approve the request here: `privatae-bastion backup requests` shows which
backup and which host, and `backup approve <id>` shows the pairing the
request came in on and its host number (this machine's own record, from
pairing), what the host says, and what the sidecar itself says, opened here
(the host number, when it was made, which backup). A sidecar of another
host's backup is refused, whatever the request calls itself: a host is given
only its own backups' keys. Restoring a lost host's backups onto the host
that replaces it is yours to do here, with `backup restore-plan`. Approving
(with the code from your authenticator, when one is enrolled for that host
here) checks the sidecar is the backup the host asked for, of a backup kept
in platform storage (`b/`) or staged there for a copy kept only here (`s/`),
and seals the same record to that host's own key alone. The
host then fetches and decrypts that backup itself. This bastion's key never
leaves this machine, and the host gets a key that opens that one backup and
no other. A host can hold at most 16 requests waiting here, or 512 KiB of them;
answering one frees its room, and a request lapses after a day. The daemon
and `backup approve`/`deny` lock the request file while they change it, and a
request file that cannot be read is set aside beside it and named by `backup
requests`, not overwritten.

When your host keeps a copy of its backups on this machine, they arrive
through `backup_fetch`, each with its sidecar, named `<stamp>.tar.zst.age` and
`<stamp>.key.age` (the stamp is the backup's UTC time, `YYYYMMDDTHHMMSSZ`).
Files named that way always land at the top of this host's backup folder,
whatever folder the host names. This bastion keeps a record, in its own state
folder, of every backup file it fetched: when it arrived, its size and its
SHA-256. After each one arrives, the folder is thinned among the files in that
record only, and only while each is still the file that arrived: the newest 7,
and the newest of each of the last 14 days, 8 weeks and 12 months, judged by
when each file arrived here, not by the name the host gave it. Files you put
there, files from before this version and anything else in the folder are
never removed. A file named `.keep-all` in the folder turns thinning off.

Each host's backup folder must be its own. A backup op is refused while the
folder is the same as another paired host's, sits inside it or contains it;
while it is or contains this bastion's configuration folder, backup keys or
backup records; or while it sits inside the configuration folder anywhere
but under its `backups` folder (the default, `backups/<host>`, is there). Set
a separate `backup_root` for each host to use one. Every host's backup folder, wherever it
is, is part of this machine's own record for ops: no op may name it as an
effect, and the sandbox hides it. One on a network mount that stops
answering is left unmasked for a run rather than stopping it, and no op may
name it all the same.

A host can list the backups held here for it (`backup_list`): each backup's
stamp, the sizes of its data file and sidecar, and their SHA-256 digests. A
listing never reads a file to hash it: a digest this bastion does not know yet
is left empty and read in the background, and appears on a later listing. A
file whose read does not return within two minutes (a network mount that
stopped answering) holds up no other folder: the background reading moves on,
reads nothing more from that folder until that read returns, and keeps its
digest if it does. The two minutes count from the last read of the file that
returned, not from the start of the file: a large backup on a slow disk whose
reads keep returning is read to the end however long it takes, and never
counts as stuck. To
restore a backup held only here, the host asks this bastion to send one of
those files to a short-lived upload address (`backup_push`): only a file named
like a backup, directly inside this host's backup folder or a folder you
shared with it, not through a link that leaves that folder; only the file
whose SHA-256 the host names, checked before anything is sent; only over https
to a public address that is not this machine's own, with the header the address was signed with (the
platform signs `If-None-Match: *`, so storage never writes over an object that
is there); that header with that value is the only one a host may hand over,
and any other header name or value is refused before a job starts, as is a
start with no headers at all (the platform always hands that one over). A push
whose file stops answering (a stat, the open or one read of it not returning
within two minutes, as on a network mount that died) fails with a sentence and
its upload is stopped, rather than staying pending. The read it was stuck in
cannot be stopped and keeps a thread and the open file until the mount
answers. Pushes and the background reading for digests keep one record of
their reads, so a folder holds at most one stuck push read and one stuck
digest read however often a push is started there, and the whole bastion at
most eight reads of both together: a start in a folder with a read of either
kind that has not returned is refused with a sentence, as is any start while
eight reads have not returned, until one does; the reading for digests skips
a folder whose push read has not returned, and reads nothing while eight are
in flight. A push that waits for its turn to read (behind a stuck read) is
not blamed for it: after two minutes of waiting it fails with a sentence
naming what it waited on, its folder's stuck read or the cap of eight. A job's status answers only the host that started it,
and no reply quotes the upload address's signature.

## Restoring a lost host
If a host is lost, a new one is made to replace it, and it restores from a
backup. The new host needs two things: that backup's key, and the backup file.

The key: the new host shows its own key under Settings > Backup > Restore.
Either this bastion reseals the backup's key to it — through a restore request
from the new host once this bastion is paired with it, when the new host has
the lost one's host number (a request for another host number's backup is
refused), or, for any host, here with
`privatae-bastion backup restore-plan --dir <folder> --stamp <stamp> --to
<the new host's key>` — or the owner does it in their browser with the lost
host's recovery key, which is also a recipient of every sidecar. Either key
works; the new host never receives either of them.

The file:

- from platform storage or your own S3 bucket, a new host finds the lost
  host's backups only if it has the same host number as the lost one;
- from this machine: pair this bastion with the new host, then share the lost
  host's folder with it, here, with
  `privatae-bastion backup share --with <new host> --from <lost host>` (or
  `--dir <folder>` for any folder). The new host then sees those backups in
  its listing as `shared/<name>` and asks this bastion to send the one it
  needs. It cannot write to that folder. `backup unshare` takes it back, and
  unpairing or revoking the new host takes back every folder shared with it.

This bastion does not bring up the new host. A Host on hardware you own is a
C-Series Host ([A Host on this machine](host-on-this-machine.md)), and it can
restore a backup the lost host made, from a file:

1. Copy the backup and its key file (`<stamp>.tar.zst.age` and
   `<stamp>.key.age`) out of the lost host's backup folder here.
2. In the C-Series Host's Backups app, under "Restore from a file", choose
   the two together and give the lost host's recovery key. The page opens the
   key file with it and seals the backup's key to the new Host; the recovery
   key never leaves the page.
3. Tick the box and enter the code from your authenticator. When the backup
   is from another host number, the page asks you first.
