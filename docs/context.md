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
audited on this machine. The vocabulary is reads plus **one write lane**: a
signed move plan that you confirmed on this machine, which archives files and
never deletes them. Dropping a grant removes the grant, not your files.
**No delete op exists.**

A grant with `search` runs the bastion agent on the folder. Its search
results, read ranges and catalog cards come from the agent's sanitized text,
and each reply says how that text was sanitized: `sanitize_mode` is the mode
in the agent's manifest, `sanitized` is true only for `sterilize`, and
`sanitize_note` says what the mode leaves in. The bastion deploys the agent in
`flag` mode, which replaces e-mail addresses, phone numbers, card, bank and ID
numbers, IP and MAC addresses and keys, and does **not** find names, street
addresses or dates of birth. So a Host reading your folder through search
sees those.
