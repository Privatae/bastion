# Model store

The host may manage which models live on this machine through the
`model:list`, `model:pull` and `model:drop` ops, under their own capability
family (`models`, separate from `inference`). Using a loaded model and deciding
what gets downloaded onto your disk are different permissions. A `model:pull`
needs your approval **on this machine**, is bound to that exact model, role and
byte ceiling, is good for one use, and is stopped if the download turns out
larger than approved. A machine with no second factor enrolled refuses
`model:pull` outright. `model:drop` refuses any model that this pairing did not
pull, so a model you fetched for your own work cannot be removed through that
op. A pull is reported available only after a behavioural probe, because a
completed download proves only that bytes arrived.

Note the boundary: those rules govern the `model:*` ops. The host's direct
traffic to the ollama forward inside the tunnel is a separate path, and it is
filtered (store-changing requests such as `/api/pull` and `/api/delete`
refused) in these cases:

- **On an anchored machine**, for every pairing, the anchor included. Changing
  which models are there goes through `model:pull` and `model:drop`. A member
  host whose grant from the anchor is **scoped to named models** also has
  every request's model name checked against that list.
- **On a local machine**, once you switch the `models` capability off for
  that host in the local console (`privatae-bastion ui`). On a root install
  kept local (`--local`), `sudo -H privatae-bastion switch <host> models off`
  does the same. On an install as your own user that command reads root's
  state, where your host is not paired, so it switches nothing; use the
  console.

Otherwise, on a local machine, that forward is a raw byte-for-byte splice to
your ollama, and the pairing itself is the authorization. A local machine
reads no grant for this, so a scope set on the host does nothing there:
switching `models` off is how you stop a host there changing your models.
The egress lane is no way around that switch: on a local machine it never
reaches this machine's own addresses (see
[the security model](security-model.md)), so ollama on loopback or on this
machine's LAN address cannot be reached through it either.
