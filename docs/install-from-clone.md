# Installing from a clone

The [README](../README.md#3-install) installs the tools from the published
module with `go install …@latest`. This is the other way: you have cloned the
repository, or been given a clone, and want to build what is in it. That is
what a contributor does, what a reviewer does to run a branch, and what
anyone does whose relay runs a build ahead of the last tag.

## What you need

Go 1.27 or later — `go.mod`'s floor, and `go version` says what you have —
`git`, and `make` if you want the shortcuts below, though every target is one
`go` command and is shown beside it. No C toolchain: every binary is pure Go,
and the relay is built static.

## Build into the tree

```
git clone git@github.com:tropeforce7/agentuucp.git
cd agentuucp
make build                      # go build -o bin/ ./cmd/...
bin/auu version
```

`bin/` holds `auu`, `auu-relay`, `auu-admin` and `auu-ca`, and is ignored by
git. Nothing outside the tree is touched, which is the form for trying a
branch: `git checkout BRANCH && make build`, and the four binaries are that
branch's.

## Install onto your PATH

```
make install                    # go install ./cmd/...
```

This puts the four programs where `go install` puts things — `$GOBIN`, or
`$HOME/go/bin` — exactly as the README's `go install …@latest` does, but
built from the clone as it stands rather than from a release. Running it again
after `git pull` is how you update. The README's
[section 3](../README.md#3-install) says how the PATH is set, and how `auu`
and `agentuucp` are one program under two names.

On a Linux host, `scripts/install.sh --from .` does the same from the clone:
`/usr/local/bin` when you run it as root, `~/.local/bin` as yourself, with
Go installed first if the host has none new enough. It installs
`auu`, `auu-admin` and `auu-ca`; `--relay` adds `auu-relay`. Read the
script's own header before you run it — it says so itself, and it is short.

## The skills

The three Claude Code skills are inside the binary, so after either install:

```
auu skill install
```

writes them under `~/.claude/skills`, and `make install-skill` does the same
by copying them out of the tree. A skill on a machine must match the `auu`
beside it, so run it again after an update.

## What version a clone build reports

`auu version` reports what the binary was built from, and from a clone that
is the git state:

| the clone | `auu version` |
| --- | --- |
| at a tag | that tag, as a release build reports |
| past a tag | `v0.0.0-20260930003231-11889e0345f7`: the time and the commit |
| with uncommitted changes | the same, with `+dirty` on the end |
| no `.git` at all | `unknown` |

That is how a relay's operator and its users tell which build they are
running, so build from a clean checkout when the number matters. The last row
is the one that catches people: a directory with no `.git` — an export, a
downloaded archive, a copied tree — carries no version at all, and there is
nothing the build can do about it. Send somebody a clone, or a tag, not a
tarball.

## The relay for another machine

The relay is deployed as a static Linux binary, built on your own machine and
carried to the host by the kit or by hand:

```
make relay-linux                # CGO_ENABLED=0 GOOS=linux GOARCH=amd64
make relay-linux ARCH=arm64     # an ARM host, a Raspberry Pi among them
```

The result is `bin/linux_ARCH/auu-relay`. The same three variables build any
of the four programs for any host Go supports — for example

```
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o out/ \
    ./cmd/auu ./cmd/auu-admin ./cmd/auu-ca
```

for an expert host on a Pi. [Deploying a relay on
Linux](deploy-linux.md) says where each binary goes on the host.

## Checking the build

```
make vet test build             # what CI runs first
make race                      # go test -race -count=1 ./..., part of done
```

`make e2e` runs the container suite and needs Docker.
[`.claude/guides/TESTING.md`](../.claude/guides/TESTING.md) says what each is
for.

## Keeping a clone current

```
git pull --ff-only
make install
auu version
auu skill install
```

A relay is updated by stopping its unit, replacing the binary and starting it
again, as the [relay document's day-two
section](relay.md) says. A database at another schema version is refused by
name rather than migrated, so read the version line before you replace a
relay's binary.
