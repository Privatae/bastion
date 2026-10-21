# Repository layout

```
client-go/        the bastion: one Go package, one binary
  main.go         CLI entry point and built-in help
  run.go          daemon: tunnel, lanes, heartbeat, control ports
  pair.go         pairing and key generation
  pair_unix.go    pairing with a Host on this machine over its enroll socket
  coder_socket.go a coder run's socket for a Host on this machine
  anchor.go       networked-mode anchor
  mgmt*.go        management lane, allowlist and audit
  auditlog*.go    every audit row also written to the system log
  writes.go       which management ops are writes (and need an approval)
  device*.go      the approval device
  quarantine.go   closing a pairing's write lanes after repeated refusals
  ops*.go         host-written ops: terms, sandbox, dry run and apply
  service*.go     service slot: servers with no network, reach grants, mirrors
  session*.go     session lane (interactive terminal)
  dcn*.go         Distributed Context Network store handlers
  context*.go     folder sharing and on-machine text extraction
  modelswap.go    model store
  inferencefilter.go  filter on the ollama forward (scoped pairings, local models switch, withheld grants)
  mirror.go       memory mirror: the host's database replica on your disk
  stepup*.go      second-factor enrolment and approvals
  agents*.go      agent observe
  freeagent*.go   the bastion agent: install, run and supervise it (see below)
  release_sign.go the release keys and the manifest signature check
  computer*.go    computer observe
  observe*.go     host observe, baseline and delta
  ui*.go          local console
  uiassets/       console HTML and CSS
deploy/
  VERSION         current release version
  install.sh      macOS / Linux installer
  install.ps1     Windows installer
  build.sh        reproducible cross-compile, shared by publish and verify
  publish.sh      release pipeline: build, sign the manifest, publish, verify
  release-sign/   the signing tool: runs where the release key is, never here
  release-verify.sh  check a manifest's signature against the pinned keys
  verify-release.sh  rebuild a published release and compare its digests
  fuzz.sh         run every fuzz target for a bounded time
  check-claims.sh  check that every test the security table cites exists
docs/             reference pages, listed in docs/README.md
LICENSE           GNU GPL v3
```

The bastion agent (repository `bastion-agent`) was first called freeagent,
and some names keep that word on purpose. They are stable names, not
leftovers, and are not renamed:

- the Go files and identifiers above (`freeagent*.go`, `fa*`);
- the agent's state directory, `/var/lib/privatae/freeagent` on a root
  install, where each installed agent keeps its key, vault and logs;
- the heartbeat fields `freeagent_ok` and `freeagent_stores`, and the
  `freeagent` capability, which the platform reads;
- the `FREEAGENT_*` environment variables the bastion sets for the agent
  process, and the `freeagent: 1` schema field of the agent's manifest.

Renaming the directory, the fields or the variables would break an installed
machine or the platform's reader for no change in behaviour, and renaming the
code would only make its history harder to follow. The public addresses were renamed:
from 0.42.0 the bastion reads only `privatae.ai/bastion-agent/version.json`
and the `bastion-agent-<version>.pyz` it names. The legacy
`privatae.ai/freeagent/` address has been retired and no longer answers.
Bastions from 0.20.0 to 0.41.x only fell back to it, so they read the new
address. A bastion older than 0.20.0 read only the old one: it finds the
address gone and keeps the agent it has installed.
