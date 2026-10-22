# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Email **security@privatae.ai** with:

- the version (`privatae-bastion version`) and platform,
- what you found and how to reproduce it,
- what an attacker could do with it.

You will get an acknowledgement within three business days. We will keep you
informed as the report is confirmed and fixed, and credit you in the release
notes if you wish.

## What is in scope

- This repository: the `privatae-bastion` binary and the installers under
  `deploy/`.
- Anything that lets a host, another machine, or another user on the same
  machine do more than the grant and the local approval allow: reading files
  outside a granted store, deleting where only archiving is allowed, running a
  program that is not in the fixed table, bypassing the second factor, opening
  a listener that is not documented in the security model
  ([docs/security-model.md](docs/security-model.md)).

## What is out of scope

- The Host the bastion connects to. It is separate software: a C-Series Host
  is [Privatae/cseries](https://github.com/Privatae/cseries), and a Host on
  Privatae's own platform is software that is not open source. Reports about
  either sent to the address above are forwarded.
- Findings that require root on the machine already. The bastion's root ops
  assume the machine's administrator is trusted.

## Supported versions

Only the current release, as published in the release manifest, receives
fixes. The bastion self-updates from that manifest, checks the manifest's
signature, and checks the digest of what it installs against it, so a fixed
release reaches every paired machine when its host directs the update.

## What you still have to trust

The bastion limits what your host can do on your machine. It cannot limit what
the bastion itself does, and the bastion comes from us. These are the places
where you are trusting us, and what stands in the way.

**The release key.** Every release manifest, for the bastion and for the agent
it runs, is signed with an ed25519 release key. The public halves are compiled
into the binary (`client-go/release_sign.go`), and a manifest that does not
verify is refused. The private key never comes to the machine that builds and
publishes releases: a release is built there, then waits until the key holder
signs it on their own computer with `deploy/release-sign`, where the key is
stored encrypted under a passphrase. Whoever holds that key and passphrase can
publish a bastion and an agent that every bastion will accept. A compromised
download server, cache or DNS record is not enough on its own: without the key
it can only serve something the bastion refuses.

The release machine is different. It builds the release and computes the
digest the key holder signs, and the signing program shows only the kind,
the version and that digest, which the key holder has no independent way to
check at that moment. So someone in control of the release machine could have
a substituted release signed during a normal publish. That would not stay
hidden: `deploy/verify-release.sh`, run from any clone of this repository,
rebuilds the published release and reports any binary that differs. But it is
found after publishing, not stopped before it.

Two keys are pinned, a primary and a spare kept offline apart from it. If one
is lost, releases are signed with the other, and a later release pins a new
spare. If both were lost, no bastion could take another update or agent until
it was reinstalled by hand.

**The first install.** `curl … | sudo sh` and `irm … | iex` run a script from
our website before any bastion exists to check anything. The installer checks
the binary's digest against the manifest, but the installer and the manifest
come from the same place. To avoid trusting that one download, build from
source (see the README) or run `deploy/verify-release.sh` before installing.

**Bastion updates.** A bastion never replaces itself on its own. Your host has
to ask, and what it can ask for is limited to what we signed: the update goes
ahead only when a signed manifest names exactly the version the host asked
for. On a machine anchored to a host, a move to a newer version needs no
approval from you, so there the signature is the only thing that stands in
the way, as it is for the agent below. A signature shows that we published a
manifest at some point, not that it is the latest one, so a move to an older
version, or to one the bastion cannot compare with its own, still needs your
approval bound to that exact version. On a local machine that is not
anchored, your host can move the bastion to an older signed release by asking.
Switching `directives` off in the local console refuses every update your
host asks for.

**Agent updates.** The agent is different: it updates without asking. While a
folder is shared with the agent, the bastion checks the agent's manifest every
ten minutes and installs any newer signed version, restarting the agent on it,
with no request from your host and no approval from you. The signature is the
only thing that stands in the way. A new agent version reads the folders you
granted, as the old one did, and is never moved to an older version than the
one installed.

**Checking our work.** Release builds are reproducible.
`deploy/verify-release.sh` fetches the published manifest, checks its
signature, checks out the release's source, rebuilds it, and compares every
binary's digest. From 0.43.0 on, each public snapshot in this repository
carries the annotated tag `v<version>`, whose message records the release's
`built_from`. That field names the commit in the repository the release was
built in, which is not a commit here, so the script uses the tag and prints
which source it used. If the digests match, this source builds the binaries we
serve. Releases published before build reproducibility was added (0.40.0 and
earlier) cannot be checked this way.

**The agent.** The bastion downloads the bastion agent, runs it, and gives it
the folder you granted. The agent is a separate program in its own repository
(`privatae/bastion-agent`), and it reads your files in order to index them. What
leaves your machine is what its manifest and your grant allow. Its extraction
and PII redaction happen inside it, so check that repository, not this one,
for how well those work.

**The Host.** The bastion holds your Host to your grant and your approvals.
What the Host does with what you share with it is the Host's own software, and
which software that is depends on where the Host runs.

- **A C-Series Host** runs on your own machine, in its own Linux virtual
  machine. Its source is [Privatae/cseries](https://github.com/Privatae/cseries),
  under AGPL-3.0-only; the bastion and the bastion agent are GPL-3.0-or-later.
  `npx cseries` installs the bastion beside it as the machine's system service
  and, on every pairing, runs `set-mode networked`, then
  `pair --redeem-url <the Host's https enroll address> --host-ca <its CA> -`
  with the token on standard input, then `claim-anchor` and
  `stepup-enroll --console-only --host <the Host>`: the machine is anchored to
  that Host and you approve its writes here with your own authenticator. No
  Privatae account is needed
  ([A Host in a VM on this machine](docs/host-on-this-machine.md#a-host-in-a-vm-on-this-machine)).
- **Optional and paid, from Privatae:** C-Series Cloud, which runs a Host on a
  server of its own that Privatae sets up and keeps patched, and a Privatae
  network membership, which joins a Host on your own machine to the Privatae
  network.
- **A Host on Privatae's own platform** is the case where the Host's software
  is not open source. There, the bastion keeps the Host to your grant and your
  approvals whatever the platform does, and what the Host does with what you
  share with it is governed by software you cannot read here.
