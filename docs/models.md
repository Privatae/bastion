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
traffic to the ollama forward inside the tunnel is filtered (store-changing
requests such as `/api/pull` and `/api/delete` refused, model names checked)
only when the pairing is **scoped to named models**, when you have switched
the `models` capability off in the local console, or when a networked
bastion's grant withholds model management. Otherwise, on a local bastion
with an unscoped pairing, that forward is a raw byte-for-byte splice to your
ollama, and the pairing itself is the authorization. Scope the pairing on
your host, or switch `models` off here, if you want the filter.
