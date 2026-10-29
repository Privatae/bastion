# Build, test and fuzz

Cloning and building are in the [README](../README.md#build-from-source).

Cross-compile the way the release pipeline does:

```sh
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-X main.clientVersion=dev" -o privatae-bastion-darwin-arm64 .
```

Run the tests:

```sh
go test ./...
```

Most parsing and judgement logic is in files with no build tag and runs under
`go test` on any OS. Some platform parsers and the Linux sandbox are in tagged
files, and their tests run only on that OS.

The walls a host's input has to get through also have fuzz targets
(`client-go/fuzz_*_test.go`): the path sandbox for store reads and move
plans, an op's declared effects and path params, service slot names, which
capability family lets a pairing run an op, and every signed record and
approval the bastion verifies. Each target states the property the wall
exists for. `go test` runs their seed inputs; to let the fuzzer search for an
input that breaks one, run each target for a bounded time:

```sh
deploy/fuzz.sh        # 20 seconds per target; deploy/fuzz.sh 300 for longer
```
