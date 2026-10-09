# The container suite

The deployment guide and the enrolling guide, run in four containers, and
then a matrix of what goes wrong in the wild: files vandalised, keys and
settings damaged, tokens and certificates run out, disks full, things pasted
wrong. Every row records what each party saw, word for word, with its exit
code and the relay's log, and judges it: `ok` when the programs said enough,
`gap` when a person would have needed more, `observed` when it is simply
recorded. The report is the deliverable as much as the pass.

    make e2e

needs Docker with Compose v2 and takes about five minutes. It builds one
image from the repository, brings the stack up, runs the tests, writes
`out/report.md` and `out/test.log`, and takes the stack down. It is run by
hand, not by CI: the containers cost minutes of a paid runner on every
push, for a suite that changes only when a guide or a fault row does.

## The machines

| container  | who                                   | what it holds                                        |
|------------|---------------------------------------|------------------------------------------------------|
| `relay`    | the relay host, reached as `relay.example.com:9443` | `/etc/auu`, `/var/lib/auu`, the credential |
| `operator` | the person who runs it, `you`         | `~/.auu-ca` (the offline authority) and the administrator's `~/.auu` |
| `alice`    | a user                                | `~/.auu`                                             |
| `bob`      | another user                          | `~/.auu`, and a second home for his other machine    |

They share one image, built by `Dockerfile` from the repository root: the
four binaries as `docs/deploy-linux.md` builds them, plus `forge` and
`upstream`, which exist only here (see below). `entrypoint-relay.sh` is the container form of
the systemd unit: it waits for a bundle to be delivered to
`/etc/auu/delivered/`, installs it as the credential the shipped settings
name, and runs the relay as `auu` on those settings, unchanged. The users'
containers run nothing until the test runs something.

The driver runs on the host and reaches each machine only with `docker exec`
and `docker cp`, the container form of ssh and scp. Nothing is published to
the host, and nothing in the suite can reach a file except the way a person
would: as that user, or as root on that box.

## The tests

`cycle_test.go` is the two guides in order, twenty-one steps from `auu-ca
init` to the day-two backup, each asserting the guide's own words. Its end
state, two enrolled users who are peers with certificates, a rotation behind
them, and bob's mailbox with a channel directory holding `default` and `bug
reports`, is snapshotted for the matrix.

`matrix_*_test.go` is the matrix, one file per family:

| family | what                                          |
|--------|-----------------------------------------------|
| M      | stored messages vandalised, on the relay and on the client |
| K      | the user's keys and settings                  |
| R      | the relay: settings, files, disk              |
| X      | expiry and rotation                           |
| N      | the network and the agent                     |
| C      | channels: the sender's listing, a closed and a not-yet-open channel, `default` removed, a channel deleted with mail queued, `close` |
| W      | watching: mail already queued, a post during the hold, a channel filter, `--fetch`, a colleague's channel added, the relay restarted under a watch, your own channels changed from the other machine |
| L      | mail left on the relay: a fetch that keeps it, a channel set to off, `auu rm` and its two flags, the same mail read on a second machine, and a mailbox filled by mail already read |
| S      | a channel answered by a program: `auu serve` with a shell script for the handler, a follow-up, a side copy's patch, two threads, a stranger, a failing handler, mail from while it was down, the long run, the hooks, the key-holding proxy with the handler given a token and never the key, and the same proxy as an account of its own that the expert cannot read the key of |
| A      | the signed allow list: a push, a stranger refused, the relay's database edited to admit the stranger and every post refused until the owner pushes again |
| P      | the card, the listing and the knock: a card pushed and found in the listing, the database edited to change a listed name and to blank a signature, a stranger's knock past the allow list and the trust that follows it, and the operator's three knock settings each met |
| F      | mail across peered relays, on `relay`, `relay-b` and `relay-c` with `dave` at the far end: a message across two relays and the reply back along the way it came, the middle relay stopped and its queue drained when it returns, a forward carrying a return path refused by a relay that no longer admits its courier, a loop, and an undeliverable unwinding two hops |
| G      | a database an older release wrote: relay A stopped, its database replaced by one built from schema 11's text with one mailbox in it, owned and moded as the unit's files are, and the relay started, which keeps a copy readable by its user alone, carries the database to this schema, says so, and serves the mailbox; the snapshot is put back after |
| V      | one peer vouching for another, across alice, bob and a fresh carol: an introduction carol adds on alice's word, with the comment saying whose word it was; a question about a key that alice answers by hand, nothing answering it by itself; and a vouch alice gives carol that carol's knock on bob carries, which bob's quarantine names as alice's word before it asks him anything |
| U      | mail from a build from the future, sealed on alice's machine by `forge seal`: a message with a critical section bob's build does not know, kept under `damaged/` with the cause `newer: section "S"` and said to need a newer auu, by name, and counted apart from damaged mail; the same as a stream, which waits on the relay unacknowledged, marked in the listing and counted every run, with `read` and `reply` answering in one sentence; and a section bob need not know, which is ignored and named in `--json` as the message is read |
| O      | the previous release, run as itself: its real `auu`, `auu-admin` and `auu-relay`, built from a clone of this repository at its tag and each checked by the version it says before a row relies on it; olive, enrolled by the old `auu` in a home of her own on bob's machine, reading a message to several from alice as a message from alice, the list named in `ignored_sections`, and her reply going to alice alone; the same as a stream; the relay swapped for the old one and every copy of a message to several taken, by bang path and as a stream; and olive writing to alice and bob on this relay, with the old `auu-admin` reading its status |

Each family restores every machine from the snapshot before it starts, and
each row undoes its own fault, so a row runs alone:

    AUU_E2E_KEEP=1 make e2e                  # once, to leave the stack up
    cd docker/testing
    go test -tags e2e -run 'TestMatrix/K/K13' -v .

A kept stack is good for re-running the matrix and not the cycle. The cycle is
the deployment guide from nothing — its first step creates the operator's
authority, and refuses to create a second one in a home that already has one —
so running it again needs `docker compose down -v` first.

Family F starts `relay-b` and `relay-c` with nothing: no settings and no bundle,
waiting for one as the unit would. A relay can be left in the one state the
harness cannot restore from, a credential under `/run` and no settings — the
entrypoint, seeing a credential, skips its wait and runs a relay that exits at
once for want of a config. `/run` is in neither of the volumes the snapshot
tars, and every recovery the harness has needs the container running, so it
cannot put that right itself. A new container has a fresh `/run`:

    docker compose rm -sf relay-b && docker compose up -d relay-b

The harness says which container is not up when this happens.

Rows are written as things a person did, with the reason they would have,
and every assertion is the exact sentence the code prints today. Where the
survey behind the plan found the reporting poor, the row asserts that
behaviour and marks itself `gap`; the suite is green, and the report says
what is missing. Fixing gaps is another plan's work.

Two switches:

- `AUU_E2E_SLOW=1` adds the rows that wait real time: a one-hour certificate
  expiring, a token five minutes past its expiry.
- `AUU_E2E_NOFAULT=1` turns every fault helper into a no-op. The rows that
  still pass are the ones whose assertion does not depend on the fault,
  which for a row about silence is expected; `reviews/IMPLEMENTATION_NOTES.md`
  lists them from the last run. Such a run writes `out/report-nofault.md`
  and `out/test-nofault.log`, and its report says in its first line that
  the faults were off: it is meant to fail, and it must never take the
  real report's name.

## The forge

No shipped binary can be told the time, and a static Go binary cannot be
lied to by a preloaded library. `forge/main.go` calls the same library
functions `auu-ca` calls, handed a different "now": an authority created
eleven years ago, or a bundle whose signing intermediates run out a hundred
seconds from now, then meets the real clock in the relay and the clients
exactly as one that had aged would. It is built into the image and never by
`make build`, and it adds no construction and no dependency.

`forge seal` is the other thing no shipped binary does: it sends what a
newer build would. From the identity in a home, through that home's default
relay, it seals one message to a peer, or with `--stream` one small stream,
carrying one section of a name the test chooses, critical with
`--critical`, and prints the relay's id for it:

    forge seal --home ~/.auu --to bob --section from-the-future --critical [--stream]

The sealing is `envelope.SealSections` and `stream.BuildManifestSections`
and the posting `internal/dial`'s client, the same calls
`internal/auu/sections_test.go` makes in process; family U is the same
thing through a real relay.

The image also carries the previous release, for family O. `run.sh` clones
this repository at the tag it names in `prev`, from the local object store
and fetching nothing, into a directory outside the repository's build
context, and
compose hands that to the build as the context `prev`; a stage of its own
builds the four programs from it by the first stage's steps and command,
for `./cmd/...` alone, into `/opt/auu-prev/bin`, off the PATH. A clone and not an archive,
because Go stamps a binary with the tag only when it is built in a
repository at that tag, and each row of the family first checks that the
old program says it is the previous release. A clone with no such tag
stops `run.sh` with the advice to run `git fetch --tags`. Each release
moves `prev`, and `prevVersion` in `matrix_o_test.go` with it.

`upstream/main.go` is the other program the image carries for the tests
alone: a stand-in for api.anthropic.com on loopback that records the method,
the path, the first six characters and the length of the key it was sent —
never the whole key — and the handler's client for it, since the containers
have neither Claude Code nor curl. The rows about the key-holding proxy use
both.

## What is not here

`systemd-creds`, the unit and `systemd-analyze` are the systemd job's
(`scripts/systemd-check.sh`), and the relay kit's `install.sh`, fresh and
`update`, is the kit job's (`scripts/kit-check.sh`): neither can run here,
since the containers have no systemd. Clock skew and nonce windows are unit tests
with an injected clock. The relay container has `CAP_SYS_ADMIN` for exactly
one row, the one that puts the message directory on a tmpfs of a megabyte;
the relay process itself runs as `auu` with nothing, as the unit runs it.
