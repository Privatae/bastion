# Contributing

Thank you for looking at the bastion. It is one Go package that ends up on
machines people own, so the bar is: nothing lands that widens what a host can
do on a machine without the person's grant and, where the design calls for it,
their approval on that machine.

## What you can do today

Issues and pull requests are welcome on GitHub, at
[github.com/Privatae/bastion](https://github.com/Privatae/bastion).
Development happens in a private repository, so an accepted change is carried
into the development repository and arrives here with the next release, as
its own commit. Sign-in on the git.privatae.ai forge is not reachable from
the internet, so issues and pull requests cannot be opened there. You can
also read, clone, build and verify a release, and fork under the GPL. Report
a security problem by email, not in a public issue (see
[SECURITY.md](SECURITY.md)).

## Checks a change has to pass

```sh
cd client-go
gofmt -l .            # must print nothing
go vet ./...
CGO_ENABLED=0 go build .
go test ./...
```

The backup tests also check this code against the age command itself when
one is on PATH or named by `AGE_BIN`; CI installs a pinned age release and
sets `PRIVATAE_REQUIRE_AGE`, so there they fail rather than skip.

The test suite covers all three platforms' parsing and judgement logic from
one `go test` on any OS. Platform-specific decisions live in files with no
build tag; only the enumerators are tagged. Keep it that way: a new judgement
goes in an untagged file with a table test. Check it with
`GOOS=windows go vet ./...` and `GOOS=darwin go vet ./...` as well: `go build`
does not compile test files, so only vet sees a test that uses a Linux-only
name.

A change to a wall a host's input goes through (a path check, a grant or
family check, a signed record's parser) also runs the fuzz targets, and adds
one if the wall has none:

```sh
deploy/fuzz.sh        # every client-go/fuzz_*_test.go target, 20 seconds each
```

An input the fuzzer finds is written under `client-go/testdata/fuzz/`; commit
it with the fix, and every later `go test` runs it.

## What a change has to respect

- **The bastion dials out.** No new listener on a non-loopback interface. A
  new listener inside the tunnel is a capability family with a grant check.
- **Fixed argv.** A management op runs a fixed command line. A caller value
  reaches a program only through a strict charset check and never as part of
  a shell string.
- **No shell in file handlers.** Ops that touch the person's files are Go
  handlers. The one that runs a program takes a tool name from a fixed table.
- **Approval on the machine.** Anything that writes to disk, downloads onto
  it, or opens a root shell is gated by the enrolled second factor. The host
  never handles the code.
- **Withhold, don't fake.** A platform with no implementation for a capability
  must not advertise it. The host has to be able to tell quiet from blind.
- **Archive, never delete.** There is no delete op on shared stores.

## Style

- Comments explain why, in plain words. State the invariant and the failure it
  prevents. No ticket numbers, no dates, no names.
- One package, files named by concern. A new concern gets its own file and
  its own `_test.go`.
- Error text that a person will read is a full sentence saying what was
  refused and what they can do about it.

## License

By contributing you agree that your contribution is licensed under the
GNU General Public License, version 3 or later, like the rest of the
repository.
