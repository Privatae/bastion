# Heartbeat and self-update

Each check-in carries the machine's capabilities, posture, agent scan,
scheduler inventory and declared tool servers (the last three only to a
pairing granted `observe`). The host can direct endpoint rotation and a self-update.
The update is fetched from the release manifest; the manifest's signature is
checked against the release keys compiled into this binary and the binary's
digest against the manifest before it is swapped. On an anchored machine a
move to a newer version needs no approval from you: our signature on the
release is the approval, and the update goes ahead only when the signed
manifest names exactly the version your host asked for. A move to an older
version, or to one this build cannot compare with its own, waits for your
approval, bound to that version. Switching `directives` off in the local
console refuses both.
