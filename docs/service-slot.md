# Service slot: a server your host built, with no network

A host can leave a server running here, such as a private git server: an
image started with every capability dropped, no new privileges, one data
directory, and **no network at all**. It serves on a unix socket, and the
host's tunnel is the only way in; the bastion checks on every connection that
the socket belongs to the server's own user. Reaching a server needs a reach
grant you approved, naming that host and that server. If the server should
mirror public repositories, this machine does the fetching over its own
connection (public internet only, https, no redirects) and pushes into the
server. It is its own capability family, `services`. Linux only, and only
where a container runtime is installed.
