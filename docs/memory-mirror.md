# Memory mirror

When your host asks for it, the bastion keeps a streaming replica of the
host's database on hardware you own: a PostgreSQL standby running the same
image the host runs, fed through a forwarder in this process that carries the
replication stream over the tunnel. The host decides whether a mirror exists
and when a copy is void; this machine holds the copy. The forwarder listens
on loopback and on the replica's private container-network gateway address,
never on all interfaces, and every accepted connection is source-checked
against the replica's subnet. The data on your disk is ordinary PostgreSQL
files, unencrypted: it is your copy, readable with your own tools, and
full-disk encryption on your machine is the protection.
