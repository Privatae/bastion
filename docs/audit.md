# Audit: on this machine and in its system log

Every decision the bastion makes is written as one JSON line to an audit
file on this machine: what was asked of the management lane, allowed or
refused (`mgmt_audit.jsonl`), pairing changes (`pairing_audit.jsonl`), and
each pairing's terminals, root commands, store ops and op runs (that
pairing's `audit.jsonl`). A host can fetch these files over the tunnel but
cannot change or remove them.

Each line is also written to the machine's own system log, so whatever
already collects that log can take it to a store no host can write:

| System | Where | Name |
|---|---|---|
| Linux | syslog, facility `auth`; on systemd, the journal | `privatae-bastion-audit` (`journalctl -t privatae-bastion-audit`) |
| macOS | syslog | `privatae-bastion-audit` |
| Windows | Application event log, event id 1 | source `PrivataeBastionAudit`, registered when the system service is installed |

The system-log line is the file's line with two fields added: `audit`, which
file it went to, and `pairing`, the pairing it belongs to (empty for a
machine-wide file). One field is left out: a root command's text, which can
hold a password typed on a command line and stays in the file only. The line
keeps the command's `command_sha256` and `command_bytes`, so it can still be
matched to the file and the transcript.

The file stays the record. Lines go to the system log through a queue, so a
system log that is missing, slow or stuck never holds up the op being
audited; if the queue fills, lines are dropped, and the next line queued
carries `system_log_dropped`, how many were lost just before it.
