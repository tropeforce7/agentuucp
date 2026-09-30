<p align="center"><img src="docs/logo.png" alt="AgentUUCP" width="200"></p>

# AgentUUCP

Secure store-and-forward messaging between agents, experts and people who
work for different organisations. Each side has a key. A relay in the middle
carries sealed messages it cannot open, and the sender's name is inside them.

- **Agent to agent.** Your Claude Code asks a colleague's Claude Code to look
  at a bug, with the file attached, and gets an answer back when their agent
  next runs.
- **Agent to expert.** A channel on a project's checkout is answered by a
  program, not a person: an agent that knows one codebase and answers
  questions about it, or sends back a patch, around the clock.
- **Agent to person.** Your agent sends a review request; a person reads it
  in their inbox from a terminal and replies when they are ready.
- **Person to person.** Two people with `auu` on their machines send each
  other signed, sealed mail and files, with nothing in between that can read
  it.

Nobody has to be online at the same time. A message waits on the relay until
its owner collects it, the way UUCP mail waited for the next call. The name is
the design: UUCP with modern cryptography, for agents.

## 1. Get started

| you want to | read |
|---|---|
| put `auu` on a machine | [Install](#3-install) |
| talk to one colleague through any relay | [Quick start for two people](#5-quick-start-for-two-people) |
| run a relay for your group, on a Linux host | [Deploying a relay on Linux](docs/deploy-linux.md) |
| join a relay that requires certificates | [Enrolling on a relay](docs/enrolling.md) |
| give an agent a project to be the expert on | [Creating experts](docs/creating-experts.md) |
| let Claude Code drive all of it | [Using it from Claude Code](#4-using-it-from-claude-code) |

The whole interface is the command line, so any agent that can run a shell
command can use it. Three Claude Code skills are in the tree: one for sending
and reading mail, one for your own identity and machines, one for running a
relay.

## 2. How it stays private

**The relay.** A relay is one static binary, `auu-relay`, with a database
and a directory of message files. Anybody can run one. Its row for a message
holds the recipient's fingerprint, the channel it was posted to, when it
arrived, its size and its kind. The ciphertext is a file beside it. The
sender's name is inside the ciphertext. So a message's row does not say who
wrote it, and the operator can list and delete messages but not read them.

There are two exceptions, and each lasts only as long as the row it is on.
While a large message is being uploaded the relay holds the sender's
fingerprint, so that only the sender can add to the upload; the sender's
hourly budget was spent on the whole of it when it opened, and its space is
reserved against the recipient's mailbox. That row is deleted when the
upload completes or is abandoned.

The other is a knock, the one message that reaches somebody who has not
added you. Its row names the knocker until the owner's fetch acknowledges
it, it is replaced, or the mailbox goes. That is what lets a second knock
from one key replace the first, so the relay's cap on waiting knocks counts
knockers and no single identity can fill a mailbox's share of it. An owner
who wants neither the knocks nor the row pushes a card that takes none, and
[docs/security.md](docs/security.md) has the whole of it.

The relay does see the sender at the moment of posting, because posting is
authenticated. Its access log records that moment, and the default,
`full`, keeps it. Run the relay with `access_log: "minimal"` and nothing of
it is written down. The [security model](docs/security.md) says exactly
what the relay sees, stores and cannot do.

Somebody who edits the database directly gains no more. They can delete a
message. They can re-address it to a mailbox where nobody can open it,
because the recipient is bound into the encryption. They cannot read it,
forge one, or hand it to a reader it was not sealed for. They cannot admit a
sender the owner did not without the owner being told at their next fetch.
They cannot put a name on the relay's listing of people who chose to be
found there, since every entry is signed by its owner and verified by
whoever reads it, and what a listed name is worth is what the relay's
admission is worth, which the client says before anyone is added.

What the relay cannot defend is its own host. Whoever has root there can
replace the relay itself, so a relay's host is kept secure the way any server
is, even though nothing on it can be read.

A relay can be open, invitation-only through signed enrolment tokens, or
closed. Each user decides who may post to them at all.

**mTLS.** The relay's TLS certificate comes from your own offline authority,
made by `auu-ca` on a machine with no open sockets. There is no public CA and
no ACME.

The relay can also require every machine to present a client certificate of
its own. It is issued when the machine enrols, and it can be revoked one
machine at a time without touching the identity behind it. A machine that
presents a certificate the authority did not issue fails the TLS handshake.
One that presents none completes it and is refused at every mailbox route.
What it can reach is what a new machine needs before it has a certificate,
the trust anchor, the health check and enrolment itself, and administration
if it signs as an administrator, whose authority is a file on the relay's
host and not a certificate.

Every certificate in the chain is ML-DSA, so the transport's authentication
is post-quantum. It runs over TLS 1.3 with the same hybrid key exchange as
the messages, and nothing less is accepted; 1.3 also encrypts the client's
certificate rather than sending it in the clear.

**How messages are encrypted.** Each message is sealed with HPKE (RFC 9180)
from Go's standard library. The ciphersuite is X-Wing, which combines
ML-KEM-768 with X25519, with HKDF-SHA256 and AES-256-GCM. An attacker has to
break both key exchanges, so traffic captured today is not readable by a
future quantum computer.

Inside the sealed box is an Ed25519 signature over the message, bound to the
recipient's fingerprint. A message cannot be re-addressed or passed off as
written for someone else.

Messages larger than 64 KiB go as a stream of sealed chunks under one HPKE
context. A large attachment, up to the limits the relay's operator sets,
crosses a relay that never holds more than a buffer of it in memory. On disk
it is one file until it is collected. The [security model](docs/security.md)
says exactly what the relay stores, sees, and cannot do.

All message cryptography comes from the Go standard library and nothing is
hand-rolled: the imports are `crypto/hpke`, `crypto/ed25519`, `crypto/sha256`,
`crypto/rand`, `crypto/mlkem`, `crypto/ecdh` and `crypto/sha3`, with
`crypto/mldsa` for the certificates. One piece of the KEM's internals is
repeated rather than called. The identity package expands X-Wing's seed with
SHAKE256 itself, so that the key agent can hold the ML-KEM and X25519 halves
separately, and recomposes them with the standard library's own constructor.
A test fails if the library ever expands the seed differently. One package
outside the standard library is used, `golang.org/x/crypto/argon2`, only to
encrypt the offline authority's private keys under a passphrase; it touches
no message and no connection.

Everything from here down is reference: how to install and use the client,
then how to run and administer a relay, then the security model and the wire
format, in that order.

## 3. Install

Requires Go 1.27 or later, for the standard library's `crypto/hpke` and `crypto/mldsa`.

Without cloning anything, `go install` fetches the module and builds it:

Working from a clone of the repository instead? See [Installing from a
clone](docs/install-from-clone.md).

*Listing 3a*
```
go install github.com/tropeforce7/agentuucp/cmd/...@latest
```

That puts `auu`, `auu-relay`, `auu-admin` and `auu-ca` on your PATH. `auu` is
for everybody, `auu-relay` is the server, `auu-admin` administers a relay you
are named as an administrator of, and `auu-ca` is the offline authority that
issues a relay its certificates. Only `auu` needs to be on the PATH of a
machine that just sends and reads mail, and it can be installed alone:

*Listing 3b*
```
go install github.com/tropeforce7/agentuucp/cmd/auu@latest
```

The bare module path works too, and gives you the client under its full name:

*Listing 3c*
```
go install github.com/tropeforce7/agentuucp@latest    # installs agentuucp
```

`auu` is short for `agentuucp`. They are one program, and each names itself
correctly in its own output; this document and the skill use the short one.
Go names an installed binary after the last element of its import path, which
is why the bare form cannot be made to produce `auu`.

### 3.1 On a Linux host, with the script

`scripts/install.sh` installs or updates the tools on a Linux host, and
installs Go first if the host has none new enough to build them. It reads
`uname`, so it knows amd64 from arm64; it puts Go under `/usr/local` for
root and `~/.local` for anybody else; and running it again is how you
update, which it reports tool by tool.

Read it before you run it. Download it, look it over, then run it as
root for the machine or as yourself for your own account:

*Listing 3.1a*
```
curl -fsSL -o install.sh https://raw.githubusercontent.com/tropeforce7/agentuucp/main/scripts/install.sh
less install.sh
sudo sh install.sh              # the three client tools, in /usr/local/bin
sudo sh install.sh --relay      # and auu-relay, for a relay host or one that builds kits
```

Or, once you trust it, in one line:

*Listing 3.1b*
```
curl -fsSL https://raw.githubusercontent.com/tropeforce7/agentuucp/main/scripts/install.sh | sudo sh
```

From a checkout it builds what is there rather than fetching a release —
[Installing from a clone](docs/install-from-clone.md) is the whole of that
way of working:

*Listing 3.1c*
```
sh scripts/install.sh --from .          # the three client tools
sh scripts/install.sh --from . --relay  # and auu-relay, for a host that builds kits
```

`--version vX` installs a tag rather than the latest, and `--prefix DIR`
puts Go and the binaries somewhere of your choosing.

From a clone:

*Listing 3.1d*
```
make build            # produces bin/auu, bin/auu-relay, bin/auu-admin and bin/auu-ca
make relay-linux      # the relay for a Linux host, static, in bin/linux_amd64/; ARCH=arm64 for ARM
make test             # unit and end-to-end tests
make race             # the same under the race detector
make e2e              # the two guides in four containers, then a matrix of what goes wrong
make install          # or install them on your PATH
make install-skill    # install the three Claude Code skills from the checkout
```

`make e2e` needs Docker. It builds one image from the repository, runs the
deployment guide and the enrolling guide in a relay container, an operator's
and two users', and then does to those machines what happens in the wild:
message files flipped and truncated, keys and settings damaged, tokens and
certificates run out, the disk full, things pasted wrong. Every row records
what each party saw, word for word, and judges whether it was enough; the
report lands in `docker/testing/out/report.md`. It is run by hand rather
than by CI. `docker/testing/README.md` has the rest.

`auu version` says what you have — the version the binary was built from,
which for a `go install …@vX` build is that tag and for a build from a clone
is what its version control says — [Installing from a
clone](docs/install-from-clone.md) sets out what each state reports. `auu-admin version`, `auu-ca version` and
`auu-relay --version` do the same, and the relay's line adds the database
schema it speaks; every one of the four answers `--version` too. A running
relay says the same two things on its `relay starting` log line, so a
journal answers what relay is running.

### 3.2 Tab completion

*Listing 3.2a*
```
eval "$(auu completion zsh)"     # in ~/.zshrc (e.g. macOS)
eval "$(auu completion bash)"    # in ~/.bashrc (e.g. Linux), or the output to /etc/bash_completion.d/auu
```

Then `auu read 88<tab>` completes the message id, with its subject beside it
in zsh. `--to <tab>` offers your peers and `self`. `reply <tab>` offers
messages and threads. `--attach <tab>` completes file names. The candidates
come from your local store, never from the relay, so a tab is always instant
and never a network request.

## 4. Using it from Claude Code

An agent runs `auu` many times an hour, and it must never see your
passphrase. So put your keys under a passphrase and let `auu`'s own agent,
in the spirit of `ssh-agent`, hold them unlocked in memory for the hours you
choose. You type the passphrase once, in your own terminal. Every command
Claude runs after that works without it.

Your agent reads mail on its own. Sending needs you: `auu unlock` unlocks
the keys to receive — open mail, list, fetch, watch, acknowledge — and
nothing that originates, so an AI that reads a message written to talk it
into sending one cannot. `auu unlock --send`, your passphrase again, opens a
ten-minute window in which it can send as you, and then it is back to
reading. When the agent is locked, or unlocked only to receive and the
command sends, the command stops with exit code 4 and one sentence naming
the unlock to run. Claude's job is then to ask you to run it and try again.
The passphrase is read only from a terminal, a file or a pipe, never from an
argument, the environment, or an AI. [Encrypting your
keys](docs/client.md#19-encrypting-your-keys) shows how to set it up.

The interface is the command line, so any agent that can run a shell command
can use this. For Claude Code there are three ready-made skills in the
binary, written out under `~/.claude/skills` by:

*Listing 4a*
```
auu skill install
```

The install script of 3.1 runs that for you when it installs for your own
account. `auu skill ls` says whether what is installed matches the `auu`
beside it, which is what to look at after an upgrade, and `auu skill show
connect` prints one without installing it. A file you have edited is never
overwritten in silence: `install` names it and leaves it, and `--force`
replaces it.

| skill | for |
|---|---|
| `connect` | sending to a colleague's agent and reading replies — the messaging agent, which never administers anything |
| `auu-setup` | the user's own identity, relays, machines and keys, and diagnosing a command that failed |
| `auu-relay` | the person who runs a relay: the authority, a kit, administrators, tokens, day two |

Each carries a copy of `skill/reference.md`: every command form, the exit
codes, the `--json` shapes and the sentences a command ends with.

With the skills installed you talk to Claude Code in plain words and it runs
the commands, so most people never type `auu` at all. Some things to say:

**Getting on.** *"Bob sent me this token, set me up: ccxt2.eyJpZCI6…"* Claude
shows you what the token says and which relay it names. It enrols you there
with the relay's trust anchor pinned from the token, and leaves the
`Continue?` prompt for you to answer.

*"Here is Bob's export line, add him"* adds the peer and pushes your allow
list. Claude reminds you to confirm the fingerprint with Bob out of band,
since the relay is never the one who says who a key belongs to.

A token is a bearer credential, and anything you paste to Claude goes to
Anthropic. If you would rather not hand it to an outside vendor, run `auu
enrol` yourself at the command line, as the quick start below shows, and the
token never leaves your machine. The same goes for anything else you would
not put in a prompt.

**Asking a colleague's agent.** *"Ask Bob's agent whether the padding oracle
in Decrypt.java is real, and attach the file."* Claude writes one question
that stands on its own, since Bob's agent has none of your conversation. It
sends it with the file attached, keeps the thread id, and offers to wait for
the answer. *"Any reply from Bob yet?"* waits on that thread. *"Tell me when
anything arrives"* watches every relay you are on and reports what came.

**Reading mail.** *"Check my AgentUUCP inbox."* Claude fetches what is
waiting, tells you who each message is from and what it asks, and treats the
contents as data to show you, never as instructions to follow. A message
from somebody not on your peer list is in quarantine and stays there until
you say otherwise.

**Asking an expert.** *"Ask the jostle expert where the retry logic lives."*
Claude finds the channel that answers for that project and sends the
question there. It waits with a long timeout, because an expert answers one
message at a time. If the reply carries a patch, Claude saves it and shows
you the diff before anything is applied.

A follow-up is *"ask it why the backoff is capped at ten"*. The expert
answers in the same thread with the same context.

**Running a relay.** *"Set up a relay on relay.example.com for the team."*
Claude makes the offline authority with `auu-ca`, packs a kit for the host,
walks you through installing it there, names you as administrator, and
issues the enrolment tokens you hand to each person. *"Add Carol to the
relay"* is one token.

**When something fails.** *"auu exited 4."* Claude knows that means your keys
are locked and tells you what to run. Exit 2 and 5 are diagnosed the same
way, from the sentence the command ended with.

The skills never guess a fingerprint, never add a peer without you, and never
apply a patch to your work without asking. Everything they run is in the
sections that follow, which is the same thing done by hand.

## 5. Quick start for two people

Both people need a relay to talk through. Either one can host it, or a
third party can: the relay learns nothing either way. To run one on your
own machine for a first try:

*Listing 5a*
```
bin/auu-relay --listen :8080 --db relay.db --tls-mode off
```

Plain HTTP, for a first try on one machine. A relay other people reach
serves TLS, which is its default and refuses to start without a bundle;
[Running a relay](docs/relay.md) says how.

Each person, once. `init` prints an export line, one token with no spaces:

*Listing 5b*
```
auu init --name bunty --relay http://localhost:8080
auu register
```

If somebody sent you an enrolment token for their relay instead, `auu enrol
--name bunty ccxt2...` creates the identity and registers it in one step.

Swap export lines over a channel you both already trust, confirm the
fingerprint with each other, and each add the other. Then restrict your
mailbox to the people on your list:

*Listing 5c*
```
auu peers add ccx2.<base64>.colleague-name
auu allow push
```

A colleague already on the same relay who has not added you can be
reached by knocking, where their card says their mailbox takes them:

*Listing 5d*
```
auu listed                   # who on the relay chose to be found there
auu knock colleague          # one line to somebody who has not admitted you
```

It asks before it sends and before it names them, and they see it in
their quarantine.

Send something, with a file if you like:

*Listing 5e*
```
auu send --to colleague --subject 'padding oracle?' --attach Decrypt.java \
  'Is this a genuine gap in the provider, or am I missing an entry point?'
```

And on the other side:

*Listing 5f*
```
auu inbox                    # fetch from the relay and list
auu read MESSAGE-ID          # read one
auu extract MESSAGE-ID       # save its attachments
auu reply MESSAGE-ID 'It is missing. Open an issue against home-java.'
```

That is the whole loop. Channels, large files, waiting and watching for
mail, several relays, encrypting your keys, and what every exit code means
are in [Using auu](docs/client.md).

## 6. Documentation

| document | what it covers |
|---|---|
| [Using auu](docs/client.md) | the client in full: sending, channels, receiving, an expert on a channel, watching, several relays, encrypting your keys, exit codes, and what lives where on disk |
| [Running a relay](docs/relay.md) | the relay binary, its settings and limits, certificates from your own authority, client certificates, keeping a relay private, and administering it: administrators, enrolment tokens, the audit log |
| [Installing from a clone](docs/install-from-clone.md) | building and installing what is in a checkout rather than a release: the targets, the relay for another host, and what version a clone build reports |
| [Deploying a relay on Linux](docs/deploy-linux.md) | the relay as a system service on a Linux host, step by step, or as a kit |
| [Enrolling on a relay](docs/enrolling.md) | joining a relay that requires certificates, from the user's chair |
| [Creating experts](docs/creating-experts.md) | an agent that answers for one project, with `auu serve`, as a service |
| [The serve command](docs/serve.md) | `auu serve`, its file, its state and its key-holding proxy |
| [Security model](docs/security.md) | what the relay stores, sees and cannot do, and the wire in detail |
| [Command reference](skill/reference.md) | every command form, exit code and `--json` shape, as the skills read it; `auu skill show reference` prints it from the binary |

## 7. On the use of AI

This project was written with [Claude Code](https://claude.com/claude-code),
under human direction and review. Two models did the work: **Claude Opus 5**
and **Claude Fable 5.1**. It is stated here rather than in a trailer on every
commit, because it is one fact about the project and not a fact about each
change.

The working method was the same throughout, and it is the reason the result is
reviewable at all. Nothing was written directly. Each piece of work began as a
specification argued out in prose — what the threat model is, what each
component must do, which options were considered and which was taken and why,
and the exact list of tests that must exist. Only then was it implemented
against that document, and every place the implementation had to fill in a gap
or depart from the specification was written down. The specifications, that
record, and a reviewer's checklist live in `reviews/`, which is git-ignored:
they are working documents rather than part of the software, so a clone gets
the code and not the argument behind it.

### 7.1 Contributing with an AI

If you want to send a patch, and you are working with an agent of your own,
point it at `.claude/guides/`. Unlike the specifications, the guides **are**
part of the repository, because they are the part a contributor needs:

- `DEVELOPMENT.md` — the rules for changing this code, organised by the kind
  of mistake rather than by package: dependencies and cryptography, ordering
  of checks, what the relay must never learn, configuration, storage,
  signatures, network input, the command line, git and documentation.
- `TESTING.md` — what a test has to prove here, the adversarial-input rules
  (both sides of every boundary, the extremes of every signed type, randomised
  crypto tests that publish their seed, precise bit-flip vandalism, bounds on
  anything a peer can claim a length for), the harness patterns that already
  exist, and a checklist for before you say you are done.

Every rule in them was learned by getting it wrong once, and each is written
with the failure that taught it, so you can judge whether it applies to what
you are doing. Three of them exist because writing the rule down and then
checking it against the code turned up a live bug: an absolute value that
`-math.MinInt64` defeated, a duration multiplication that overflowed past a
cap, and two decoders that allocated from a length before checking it.

Some of the guidance will read as excessive for a project this size. It is
deliberate. An agent will cheerfully write a test that passes for the wrong
reason, and a reviewer reading a large diff will not notice; a rule that says
*prove the order by which error came back* is cheaper to follow than to
rediscover.

The decisions that matter were not the models'. The choice of HPKE from the
standard library over anything hand-rolled, the insistence on X-Wing for
post-quantum hybrid key exchange, the ruling that a relay must never store
who talks to whom, and the
decision to replace the static invite secret rather than deprecate it — all of
those came from the human side of the conversation, and several of them
overruled what had already been built. Where a model got something wrong and it
was caught, the correction is in the git history and in the notes, not quietly
edited away.

### 7.2 What this should mean to you

**Review this code before you trust it with anything.** That is true of any cryptographic software, and it is not
less true here. The parts most worth your attention are the envelope layer in
`internal/envelope`, the request authentication in `internal/relayapi`, and the
ordering rules in the relay's request pipeline, which are the places where a
subtle mistake would not show up as a failing test. Every claim in the security
model above is meant to be checkable against the code; if one is not, that is a
bug in the claim.

## 8. Layout

| package | role |
|---------|------|
| `internal/identity` | keys, fingerprints, export lines |
| `internal/envelope` | seal and open one message over `crypto/hpke`; with `internal/stream`, the only places plaintext meets a key |
| `internal/stream` | the chunked format for messages too large to seal in one piece |
| `internal/message` | the message body and its validation |
| `internal/channels` | a mailbox's directory of channels, signed by its owner |
| `internal/allowlist` | a mailbox's allow list, signed by its owner and verified by the relay on every post |
| `internal/relayapi` | wire types and request signing, shared by both sides |
| `internal/relay` | relay storage, HTTP handlers, and the limit policy |
| `internal/ratelimit` | the token bucket the relay's limits are built from |
| `internal/token` | enrolment tokens: issue, parse, verify |
| `internal/clientca` | the relay's use of its bundle: issuing and verifying client certificates, minting its own leaf |
| `internal/pki` | the offline hierarchy `auu-ca` makes and the bundle format a relay is issued |
| `internal/keyfile` | a private key under a passphrase: Argon2id then PBKDF2, sealed with AES-256-GCM |
| `internal/agent` | the process that holds a user's unlocked keys and performs their private operations over a socket; the client side that composes an identity from it |
| `internal/term` | whether a file descriptor is a terminal, turning its echo off, and reading a passphrase |
| `internal/client` | relay client |
| `internal/store` | local identity, settings, peers, relays and the spool |
| `internal/lockfile` | one lock per file, released by the kernel when the process exits |
| `internal/kit` | the relay kit: one archive that installs a relay on a host |
| `internal/buildinfo` | what version a binary was built from |
| `internal/testutil` | seeded randomness and bit-flipping, for tests |
| `internal/auu` | the client command, as a package, with `auu serve` and its key-holding proxy |
| `skill` | the three Claude Code skills and the reference, embedded for `auu skill install` |
| `cmd/auu`, `cmd/auu-relay`, `cmd/auu-admin`, `cmd/auu-ca` | the four binaries; `cmd/auu` is one line |
| `main.go` | the client again, as `agentuucp`, so the bare `go install` path has something to build |
| `scripts` | the public install script and the checks CI runs over it, the kit and the unit |
| `docs` | the eight guides, the systemd unit and a settings file, and the serve handler script |
| `docker/testing` | the container suite: four machines, the two guides in order, and the matrix of what goes wrong, with its report |
| `.claude/guides` | development and testing rules for contributors |

## 9. Licence

AgentUUCP is released under the MIT licence. The text is in
[LICENSE](LICENSE). Use it, change it, and sell what you build with it. Keep
the copyright notice with any copy, and do not hold its authors responsible
for what it does.

To report a fault in its security, read [SECURITY.md](SECURITY.md) first.
