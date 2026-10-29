# Your files: context and DCN stores

## Context: your files, turned into text here
`add-folder` hands a folder to your network. `privatae-bastion context` opens a
browser page, running as **you** (not as the daemon), that shows exactly the
files you can already open and asks the host before anything is added. The
bastion can also turn bytes into content on your own hardware before anything
leaves: OCR for scanned documents, speech-to-text, office-document extraction
and video frames. Anything that turns your bytes into their content runs on
your machine, never on the platform.

## Distributed Context Network (DCN) stores
Signature-verified store grants for folders you share. The host's verify key is
pinned on first sync (trust on first use) and a later key change is refused.
Every read is sandboxed to the granted path, walks no symlinks out of it, and is
audited on this machine. The grant's excludes hold on every read and move: a
pattern of one name (`.ssh`, `*.key`) matches that name at any depth, and a
pattern with a `/` (`.config/gcloud`) matches that run of folders at any depth.
The bastion agent's own folder, `.agent`, which holds the plaintext of every
file the agent read, is never served or moved, whatever the grant excludes. The vocabulary is reads plus **one write lane**: a
signed move plan that you confirmed on this machine, which archives files and
never deletes them. Dropping a grant removes the grant, not your files.
**No delete op exists.**

A grant with `search` runs the bastion agent on the folder. Its search
results, read ranges and catalog cards come from the agent's sanitized text,
and each reply says how that text was sanitized: `sanitize_mode` is the mode
in the agent's manifest, `sanitized` is true only for `sterilize`, and
`sanitize_note` says what the mode leaves in. The bastion deploys the agent in
`flag` mode, which replaces only what a pattern can find: e-mail addresses,
phone numbers, card numbers, US social security numbers, IBANs, US bank
routing numbers written after a word like "routing", Bitcoin addresses that
start with 1 or 3, IP and MAC addresses, private keys, and access keys and
tokens of the kinds it knows. It does **not** look for names, street
addresses, dates of birth, passport, licence and other ID numbers, other bank
account numbers or other crypto addresses. So a Host reading your folder
through search sees those.
