# Development guide

For an agent, or a person, contributing to this project. Every rule here was
learned by getting it wrong once. The rule comes first; what went wrong comes
after it, so you can judge whether it applies to what you are doing.

Read `CLAUDE.md` first. It is short and it wins over anything here. The
specifications live in `reviews/`, which is git-ignored; if that directory is
empty on your machine, ask for its contents rather than reconstructing a plan
from the code.

## Before you write anything

**Work from a written specification, and record every departure from it.**
Each piece of this project began as a prose document: threat model, what each
component must do, which options were considered and why one was taken, and
the exact tests that must exist. The implementation followed the document, and
every gap it had to fill or rule it had to break went into
`reviews/IMPLEMENTATION_NOTES.md` with the reason. That record is what makes
the code reviewable by someone who was not there. A change without a plan, or
a departure without a note, is the thing most likely to be reverted on review.

**Do not bundle unrelated work.** A project rename was on the table for the
whole of the rate-limiting work and was kept out of it on purpose. Ordering,
naming and refactoring changes hide the change that matters.

**Run `make vet test build` before you say you are done.** `make vet` runs
`gofmt -l` as well as `go vet`; a file that is not gofmt-clean fails it.

## Dependencies and cryptography

**Standard library only, plus `modernc.org/sqlite` and
`golang.org/x/crypto/argon2`.** That is the whole list. The Argon2 exception
is scoped to `internal/keyfile`, which puts `auu-ca`'s private keys under a
passphrase: the standard library has PBKDF2 and nothing memory-hard, and a
hand-written Argon2id would mean a hand-written BLAKE2b under it, which is
exactly what this project does not do. It brings `x/crypto/blake2b`. Nothing
on the wire touches either. An earlier exception for
`golang.org/x/crypto/acme/autocert` is gone: `PLAN-SELFCA.md` removed ACME and
`x/net` and `x/text` went with it. Check `go.mod` is unchanged before
reporting completion, and note that the CI dependency job names the allowed
packages exactly, so widening the list is a deliberate edit in two places.

**When you say "standard library", check the import path.** The first
implementation of the hybrid KEM was a hand-rolled X-Wing combiner in
`internal/xwing`, over `crypto/mlkem` and `crypto/ecdh`, and it was described
as standard library because the primitives underneath it were. It was
byte-compatible with what `crypto/hpke` does and entirely redundant, since Go
1.26's `crypto/hpke` already ships `MLKEM768X25519`. The whole package was
deleted. If you find yourself writing a KEM combiner, a key schedule, or an
AAD layer, stop: the standard library almost certainly has it, and if it does
not, that is a design conversation, not a coding task.

**Know that TLS's hybrid and HPKE's hybrid are different constructions with
reversed names.** TLS uses `X25519MLKEM768` (curve id 4588, plain
concatenation into the TLS key schedule). HPKE uses `MLKEM768X25519`
(X-Wing, a SHA3-256 combiner with a six-byte label). They are not
interoperable and are not the same thing. Say which one you mean.

**The hybrid stays hybrid. Do not "finish" the migration to post-quantum by
dropping the classical half.** `MLKEM768X25519` combines ML-KEM-768 with
X25519 so that an attacker must break both, and the client certificates added
later are ML-DSA-65 for the matching reason: level 3 throughout. It is tempting
to read a system that is part classical as half-done and to reach for pure
ML-KEM, and that would be a downgrade, not a completion — the classical half is
what covers ML-KEM being young. The maintainer settled this on 2026-09-08, having
been asked directly. The identity's Ed25519 signatures are a separate question, open
rather than settled, and changing them is a wire-format break with a migration
story, not a swap.

**An identity's algorithms live inside its fingerprint, which is what makes
them un-downgradable. Keep it that way.** `internal/identity` has a suite
registry, and a bundle of any suite but the original carries its identifier in
the first byte. The fingerprint is a hash over the whole bundle, so a suite is
part of an address rather than a property of a session: nobody can present the
same fingerprint with weaker keys behind it, because that is arithmetically a
different fingerprint. Two checks enforce it and both must stay —
`client.FetchKey` refuses a bundle whose fingerprint is not the one requested,
and `envelope.Open` refuses a `from` that is not the hash of the bundle beside
it. If you ever find yourself adding a field that says which algorithm to use,
separate from the key material it applies to, stop: that field is a
negotiation, and a negotiation is a downgrade waiting to be found.

**Two formats can carry exactly one signature length, and it is not an
oversight.** The envelope's sealed plaintext is `signature || inner`, and the
stream's chunk 0 is `signature || manifest`, both split at a fixed offset —
while the only thing that says which suite signed is `FromBundle`, inside the
part you cannot reach until you have split it. Adding an identity suite whose
signatures are a different length therefore needs a format version, not a new
constant. `TestSignatureLengthMatchesTheDefaultSuite` and
`TestSignatureSizeMatchesTheDefaultSuite` fail loudly and say so. The envelope
is the easy one: `Envelope.V` is outside the ciphertext, so version 2 can lay
the plaintext out as `inner || signature` and a reader knows which to expect
before decrypting. The stream is the hard one: its version is *inside* the
sealed manifest, so version 2 has to find somewhere else to say so. The stream
also fixes `EncSize`, so a suite with a different KEM needs the same bump.

**Bind context into the HPKE `info` string, not into a separate AAD layer.**
The recipient fingerprint lives in `info`; RFC 9180's key schedule already
covers it, and a re-addressed envelope simply fails to open. An extra AAD
construction on top would be a second thing to get wrong for no gain.

## Ordering of checks

This is where the project's real bugs were. Every one of them was a correct
check done in the wrong order.

**Verify a signature before you do anything a caller could exploit by
failing it.** The relay used to consume the replay nonce before verifying the
request signature, which meant anyone on the internet could write rows into
the nonce table by sending garbage. It now verifies first; replay protection
is unchanged because a replayed request has a good signature and a spent
nonce.

**Verify before you charge.** A well-formed request with a wrong signature is
verified *before* its source address is charged against the
unauthenticated bucket. Charge first and a neighbour behind the same NAT can
empty the bucket and lock a legitimate user out of authenticating. The
neighbour costs one signature check per request, which the in-flight cap
bounds.

**Key rate limits by the verified identity, never the claimed one.** The
per-identity buckets are only reachable after `checkSignature` succeeds, so
nobody can spend another user's budget by naming their fingerprint in a
header.

**Check blocks after the signature has verified, and after the rate limit.**
Before the signature, the block list becomes an oracle any unauthenticated
caller can read fingerprints out of. Before the rate limit, a blocked identity
gets an unbounded number of free refusals.

**Refuse an unparseable auth header without touching the database.** It
cannot have come from a working client, so it is the cheapest possible
rejection. There is a test that closes the store and then sends such a
request; any database read would surface as a 500.

**Reveal nothing about the token table until the token's signature has
passed.** At enrolment the order is: parse, issuer in the admin set, signature,
use, audience, time window, subject, and only then the database. A failed
enrolment consumes nothing.

**Answer 401, not 403, to a non-administrator on an admin route.** Otherwise
an outsider learns who administers the relay by watching which fingerprints
are told they are not one.

**Never take the absolute value of a signed integer from the wire.** There is
no correct `abs` over a two's-complement range: `-math.MinInt64` is
`math.MinInt64`. `FreshAt` did this, and a timestamp chosen to make the
subtraction wrap was reported fresh. Write the comparison that does not need
one: two bounds, no subtraction. The same goes for multiplying a number from
the wire into a `time.Duration`; clamp before the multiplication, not after.

**Settle the mailbox cap and blocks before looking at a token.** A registration
refused by the cap must not have spent the holder's token. Inside
`Store.Register` the order is: existing row, cap, token, insert.

## The relay stays dumb

**Return stored bytes verbatim.** The relay used to re-parse each envelope on
the read path and silently skip any that failed. A row that failed could never
be delivered, never be acknowledged, and sat in the database forever. It now
hands back what it stored and the client decides; undecodable bytes are
surfaced as a nil envelope so the client acknowledges and clears them.

**Log a fingerprint only once a signature has proved it.** The access log
took the fingerprint from the request header, so anyone could seed the log
with an identity they did not hold. `verified(w, fp)` is called only after
`checkSignature`.

**Never log a body, a token string, or anything else that is a credential.**
There is a test that enrols with a token and greps the whole log for it.

**Names are local labels.** A display name that arrives on the wire is
discarded; `envelope.Open` clears `sender.Name`. Peer names come from the
local `authorized_peers` file and nowhere else, and they must be unique
locally so `--to alice` can never be ambiguous.

**The relay routes by a label the owner published; it never sees why.** A
channel name is in the clear on the outer envelope and on the open-stream
request so the relay can refuse a post to a channel that does not exist or is
not open, and that is the whole of what it does with it: the name is checked
after the allow list, so a sender the owner has not admitted learns nothing
about which channels exist, and before anything is stored or charged, so a
refused channel costs nothing; it is written to the row and served in the
owner's listing, and no log line names it under either access-log mode. What
the channels are for is the owner's business with their senders: the relay
keeps the signed directory to serve it back verbatim and unpacks it only as
far as a name and its period, which is what a post is checked against.

**Absent means old, so a field this relay always sends has no `omitempty`.**
`queued` on a listing and `channel` on every listed message are always
present from a relay that has them, so a client reads their absence as a
relay from before the field and says nothing, rather than as zero or as
`default`. The fields a sender may leave out — the outer `ch`, the inner
`channel`, the manifest's, the open-stream request's — are the other way:
absent means `default`, and a message sent for `default` is byte for byte
what it was before channels. Keep the two rules apart: one is about what a
relay says, the other about what a sender says, and a test marshals the
zero value to prove the tag.

**A listing held open is the owner's listing answered later, and over its
cap the hold degrades rather than refusing.** `GET /v1/mailbox/{fp}?wait=D`
subscribes to the notifier under the mailbox's mail key and every watched
peer's directory key, looks once, and only then waits on the wake channel,
the request's context and a timer, so a row that lands between the look and
the wait has already closed the channel; on a wake it looks once more and
answers whatever is there, which may be nothing, and never loops. A relay
already holding `max_waiting` listings, or two for one identity, answers
the request at once as a relay without the hold would, and logs
`limit=waiting` on the `status=200` line so an operator can see why a
request that asked to be held was not; nothing about the hold ever answers
`503`, since a flood of watchers must not make the relay refuse anyone.
A held request keeps its in-flight slot, which is why `max_waiting` must
sit well under `max_inflight`. A peer the watcher may not post to is
dropped from the watch before anything is subscribed, without a word: a
wait that never ends must not be a way to learn about a mailbox whose
owner has not admitted the watcher.

**Validate anything that becomes a filename or a path segment before it gets
near the filesystem or the database.** Message ids are 32 lowercase hex;
fingerprints are 64 lowercase hex. A signature proves who wrote a value, not
that the value is safe.

## Configuration

**Defaults, then the file, then the flags actually typed.** A flag left off
the command line must never overwrite a file value with its own default. The
only correct implementation is `flag.FlagSet.Visit`, which walks the flags
that were set; reading every flag's value does the wrong thing.

**Go's `flag` package stops at the first positional argument.** `auu read ID
--json` silently ignored the flag. `parseArgs` in `internal/auu/main.go` loops
over `Parse` collecting positionals wherever they appear. Every command must go
through it.

**Keep operator defaults in the library, not the command.** `DefaultLimits()`
lives in `internal/relay`; `cmd/auu-relay` populates its config from it. A
zero-value `relay.Config` is unlimited, which is what the library should do;
having opinions about numbers is the command's job. There is a test that
fails if the two drift.

**Zero means unlimited, everywhere, and it must be cheap.** A limiter built
with rate zero allows everything, allocates nothing, and takes no locks.

**Unknown config keys are an error.** A misspelled key that silently does
nothing is the worst kind of misconfiguration.

**`encoding/json` HTML-escapes by default.** `--print-config` rendered
`<redacted>` as `<redacted>`. Use a `json.Encoder` with
`SetEscapeHTML(false)` for anything a person reads or pastes back in, and test
that the printed form loads again.

**A struct that is printed as the config file cannot carry non-config
state.** The startup warning about file permissions is returned beside the
`Config`, not stored on it, because `Config` round-trips through
`--print-config`.

**Reject what a public CA will never issue for.** `localhost` and other
single-label domains are refused at validation so the failure is at startup
with a clear message, not at the first handshake with a confusing one.

**Pin the ACME host whitelist.** Without it, any client naming an arbitrary
host in SNI triggers issuance for it and burns the rate limit.

## Storage

**One SQLite connection.** `MaxOpenConns(1)` with `busy_timeout`. That means
every statement inside a transaction must go through the `*sql.Tx`; calling
`s.db` from inside an open transaction deadlocks.

**Counters, not aggregates, and adjust them in the same transaction as the
row.** Per-mailbox and relay-wide queued totals are columns updated inside
`Put`, `Delete`, `Deregister` and `PurgeMailbox`. Never `SUM` the messages
table on a hot path. `OpenStore` reconciles the counters from the messages
table every time and reports how many were wrong, so a crash between two
statements self-heals; that reconciliation is a backstop, not the mechanism.

**Version the schema and refuse what you do not understand.** `PRAGMA
user_version` is the contract. A version above the current one is refused; a
version-zero database with tables in it is from before versioning and is
refused with a message saying to delete it. Migrations are an ordered list,
each in its own transaction, each setting the version on the way out, so an
interrupted upgrade resumes rather than half-applies.

**Share DDL between the fresh-create path and the migration that introduces a
table.** Each table is one `const` used by both, so a database created from
nothing and one migrated forward store byte-identical `CREATE` text. A test
compares `sqlite_master` between the two.

**Do not store what the relay does not need.** There is deliberately no
column recording which token created which mailbox. That link appears once in
the operator's audit log and nowhere in the database: a permanent table of who
invited whom is a social graph of a different kind. The same reasoning is why
the relay stores no sender on a message.

**A service's record of what it has done is a file it writes, and nothing
else.** `auu serve` decides what to answer from `serve/ledger.json` alone.
Not from whether a message is unread: that mark is the owner's, and an
owner reading their own expert's mail must not silently kill the answer.
Not from the watch either: a watch's baseline is "now", so anything that
arrived while the service was down or busy would be lost if the watch were
the source. The watch is a wake-up and never a record; the round that
follows it looks at the ledger and the spool and works out for itself what
is pending. The ledger also carries the thread and the channel of every
message, so that a thread's turns are a count over it rather than a walk of
the spool that a removed message would falsify.

**A field that says how something was when you loaded it is not a field
that says how it is.** The ledger has an `existed` flag, which the
first-start rule turns on: with no ledger, the mail already in the inbox is
old mail and is left alone. It was set at load and nowhere else, so the
long-running service wrote the ledger in its first round and then treated
every round after it as a first start too, entering each new ask as skipped
and answering nothing, for ever. Every test went through a fixture that ran
one round before the service started, so the ledger always existed and
nothing showed it. The fix is one line where the fact lives — a ledger that
has been written exists, so `save` sets it — and the tests that would have
caught it start the service against a home that has never served. A
behaviour that is only true the first time needs a fixture that has never
run.

**A failed insert is only a duplicate if the row is actually there
afterwards.** `UseNonce` and `AddToken` re-query after a failed insert. Reporting
every failure as a replay or a duplicate would hide a broken database behind a
401 or a 409.

## Signatures and tokens

**One identity key signs five things, so each has its own domain string.**
`ccx-http-v1` for requests, `ccx-sig-v1` for messages, `ccx-token-v1` for
enrolment tokens, `ccx-stream-sig-v1` for a stream's manifest,
`ccx-channels-v1` for a mailbox's channel directory. There is a test that a
signature over the same bytes in one domain does not verify in another, in
both directions. Add a sixth thing to sign and you add a sixth domain and a
sixth test.

**An HPKE context cannot be rewound, so seal to disk before you upload.** A
stream is one context and a run of chunks; the nonce counter advances on every
`Seal` and never goes back. A chunk the network lost cannot be sealed a second
time and cannot be skipped, so there is exactly one sequence of bytes that will
ever open. `auu send` seals the whole stream into `outbox/` first and only then
uploads it, which costs one times the payload in disk and is what makes
`--resume` possible at all. The same rule holds on the receiving side: a
download that drops is resumed with a `Range` request *inside the same
process*, because the recipient context is still open there and cannot be
reconstructed anywhere else.

**A key that is not here is not a key that is wrong.** With the identity in
the agent, a private operation can fail because the agent is locked, and
that failure arrives at the same place a bad ciphertext does: `hpke.Open`
returns an error, and `auu inbox` acknowledges and discards a message that
does not open, because nobody will ever read it. A locked key would have
lost mail. `identity.ErrLocked` is in the chain of every remote private
operation, `envelope.Open` keeps the chain, `stream.OpenManifest` keeps it
for that error alone, and both receive paths check it before they call
anything unreadable. `crypto/tls` builds a fresh error around a signer's
and loses the chain, so the CLI's `isLocked` reads the agent's message
text too; the text is a shared constant. If you add a place where a
private operation's failure is treated as final, check for `ErrLocked`
first, and write the test that locks the agent after the request was
signed, because one that locks it before proves nothing.

**Do not let a transport failure look like a cryptographic one.** A stream that
stops early and a stream that was truncated by an attacker arrive at the AEAD
as the same thing, and the answers are opposite: one should be retried, the
other should be acknowledged and thrown away. The receiver knows how long the
range is before it asks for it, so an early EOF is settled as a dropped
connection at the wire layer and never reaches the crypto. When you wrap a
transport error that is about to cross into the stream package, wrap the text
and not the error — `%v`, not `%w` — so `errors.Is(err, io.ErrUnexpectedEOF)`
stays false and nobody downstream mistakes it for the end of a stream.

**`ccx` in a constant is not a leftover: it is on the wire.** The binaries are
`auu`, `auu-relay` and `auu-admin`, and the project is AgentUUCP, but fourteen
constants deliberately still say `ccx` — the nine `ccx-*-v1` domain
separators, the `ccx1` and `ccx2` export-line prefixes, the `ccxt1` (read)
and `ccxt2` (written) token prefixes, and the `X-CCX-Auth` header. Every one
of them is either inside a signature, inside an HPKE `info` string, or in a
format two machines have already agreed on. Renaming any of them invalidates every
identity, message and token in existence and silently breaks compatibility with
any deployed relay. If a future rename tempts you, rename the commands and
leave the wire alone. When a format does have to change, do what `ccx2` did: a
new prefix, the old one still read, only the new one written.

`X-CCX-Token` used to be on that list and is now retired rather than renamed:
the enrolment token moved inside the certificate request, where the signature
covers it, and a header could never be covered by one. The name survives in
`internal/relay` as `legacyTokenHeader`, read only so that a client still
sending one is told what changed instead of being refused for a missing token.

**When a standard attribute exists for what you are putting on the wire, use it
and accept the encoding work.** An earlier draft of the client certificate
plan invented an extension under a private OID to carry the enrolment token in
a certificate request, because `crypto/x509` will not write PKCS#9's
`challengePassword` and hand-assembling the request is about a hundred and
twenty lines of `encoding/asn1`. That was the wrong trade. An invented OID is a
constant this project would have to allocate from an arc it owns and then never
change; `challengePassword` already exists, is what SCEP and EST use for
exactly this, and means `openssl req -text` explains the request to an operator
for free. Encoding work is a cost you pay once. A wire constant of your own
invention is one you keep paying.

**Verify before you decode, and act only on what you decoded after
verifying.** `token.Parse` decodes a payload so a caller can find the issuer's
key, and documents that nothing it returns may be trusted. `Verify` checks the
issuer's fingerprint against the key, then the signature over the raw bytes,
then decodes those same bytes again and returns that. Claims a caller acts on
have only ever come from a verified payload.

**Sign the bytes you send; do not canonicalise.** The token signature covers
the payload exactly as it appears in the token. There is no canonical JSON
step for two implementations to disagree about.

**Every field always present, no `omitempty`, unknown fields rejected.** A
field that sometimes vanishes is a field two implementations will eventually
disagree about. `DisallowUnknownFields` on the way in: a token is not a place
for extensions one side understands and the other ignores.

**Retries must re-sign.** A request signature covers a nonce the relay spends
once. `client.do` builds and signs a fresh request per attempt; replaying the
first attempt's signature would be refused as a replay, correctly.

**Sentinel errors, not string matching.** `token.ErrForm`, `ErrSignature`,
`ErrIssuer`, `ErrUse`, `ErrExpired`, `ErrNotYetValid`; `relay.ErrMailboxFull`,
`ErrTokenSpent` and so on. The relay maps each to its message. Anything
unrecognised falls through to the least informative answer, so a new failure
mode cannot accidentally become a more informative one.

**When two packages depend on the exact wording of a message, make it a shared
constant.** `relayapi.MsgMailboxFull` and `MsgRelayFull` exist because `auu
send` tells the two apart to decide whom to advise. A string literal in two
places is a latent bug.

## Network input

**The relay reads no `X-Forwarded-For` and believes no forwarded
certificate.** Reverse-proxy support — `limits.trusted_proxies`, the
`X-CCX-Client-Cert` header, the nginx block in the guide — was removed on
2026-09-12: the relay terminates TLS itself, on its own port, and that is the
only arrangement. Per-address limits key on the connection's own address. If a
proxy is ever wanted again it is a plan of its own, not a header check added
piecemeal, because a believed header is a budget anyone can spend.

**Rate limiting must never fail a request over a bookkeeping problem.** An
address that will not parse goes into one shared bucket keyed `"unknown"`
rather than being refused.

**Health is exempt from every limit.** Monitoring that flaps during an attack
tells the operator nothing.

**Retry-After is an integer number of seconds, never a date, never zero.**
Rounded up; a zero would invite the client straight back into a refusal.

**`ServeMux` sets `Request.Pattern` on a copy the outer middleware never
sees.** If you need the matched route in the outermost handler, record it at
registration time.

**Release the in-flight slot with `defer`.** A handler that panics is recovered
by `net/http` per connection, and a slot leaked there never comes back.

**`Server.Close` before `Shutdown`.** `http.Server.Shutdown` waits for every
request in flight, and a listing held open for a watcher is in flight for
up to a minute against twenty seconds of grace, so a shutdown that went
straight to `Shutdown` would wait out the grace, cut the hold off, and
report the drain as a failure. `auu-relay`'s `stopServing` calls the relay's
`Close`, which wakes every held listing so each answers with what it has,
and only then drains. `TestStopAnswersHeldListingsBeforeTheListenerDrains`
holds one and proves the stop returns at once; without the `Close` it fails
on the grace running out. The test harness in `internal/relay` does the
same in its cleanup, since `httptest.Server.Close` waits the same way.

## The command line

**Destructive commands say what will go, then ask.** `mailboxes rm` fetches
the mailbox first and names the queued message count. `--yes` skips the
prompt; nothing else does.

**Write nothing before the confirmation prompt.** `auu enrol` shows the token,
asks, and only then creates the identity. A declined prompt leaves the home
exactly as it was, and there is a test for it.

**Do not silently move somebody's identity to a new relay.** `auu enrol` with an
existing identity configured for a different relay stops and says to use
`auu register --token` instead.

**Print a credential on its own last line so it can be piped, and nowhere
else.** `token issue` puts the summary above and the token last. `token ls`
shows ids, never token strings.

**Errors say which knob to turn.** A 429 names the limit; a config validation
failure names the setting and what to do; a "not an administrator" message
says which file the export line goes in and how to print the line.

**Two programs that may prompt must not share a terminal at the same time.**
The deployment guide told an operator to run `auu-ca relay --out - | ssh
HOST 'sudo systemd-creds encrypt …'`. A pipeline starts both sides at once;
`auu-ca` asks for its passphrase on the terminal with echo off while `ssh`
asks for a password on the same terminal, each reads some of what is typed,
and `ssh` reports the correct password wrong three times while `auu-ca`
waits for a passphrase it never quite gets — reproduced against a Debian
container with password login. And `sudo` needs a terminal it cannot have
on the right of a pipe without `-t`, which would feed the pipe into it. The
recipe is now one command per prompt — `auu-ca relay --out FILE`, `scp`,
`ssh -t … sudo systemd-creds encrypt`, `rm` at both ends — with the
no-disk form (`--out -` into a shell variable, `ssh` to `/dev/shm`, then
`ssh -t`) as the alternative and the one-liner described as right only
when nothing on the right prompts. When you write a pipeline into a
document, count the prompts; if there could be two, sequence them.

**Exit codes are a contract with the skill.** 1 usage, 2 transport, 3 timeout,
4 a human must unlock the keys.
A final 429, 503 or 507 is a transport failure.

**The skills name only commands that exist, and every command is named.**
`internal/auu/skills_test.go` reads each `skill/*/SKILL.md` and
`skill/reference.md`, takes every backticked `auu`, `auu-admin` and `auu-ca`
form, and checks it against the three programs' dispatch switches — the
authority, where a usage block is only a description of one. It checks the
other way too: a command the dispatch knows and the reference does not name
fails, unless the test's `undocumented` map excuses it with a reason. So a
command added, renamed or removed is a failing test rather than a skill
that misleads an agent, and a new command belongs in `skill/reference.md`
in the same commit as itself. `auu channel keep` shipped without its line in
the usage block because nothing checked; this is that check.

**Keep `auu-admin` a separate binary.** The privilege boundary is then visible
in what is installed where, the skill can be told never to run it, and an
administrator can keep a dedicated identity in its own `AUU_HOME`.

**The kit's unit and settings template are copies of `docs/systemd/`'s,
held equal by one test.** `//go:embed` cannot reach outside a package, so
`internal/kit/auu-relay.service` and `internal/kit/relay.json` are copies,
and `TestTheEmbeddedFilesAreTheShippedOnes` in `internal/kit` fails unless
each is byte-equal to the shipped one. Edit both, or the test says so. The
plan first said "one home" for the two; that was a sentence the mechanism
could not honour.

**A kit is a secret, and no test writes one outside a temporary
directory.** The archive holds the relay's two signing keys in the clear,
which is why `auu-ca kit` writes it 0600, records it so `show` nags, and
prints the recipe that deletes it at both ends. Every test that builds one
builds it into memory or into `t.TempDir()`, and `kit.Check` runs every
rule before `auu-ca kit` issues the bundle, so a refused kit records no
rotation for an archive that was never written.

**`scripts/kit-check.sh` is the kit's proof, and runs in CI as the guide's
does.** It is `auu-ca kit` and `install.sh`, fresh and as `update`, under
a real systemd: what the script installs, refuses, backs up, keeps and
repairs, each an `ok:` line. Anything `install.sh` does is proven there
and nowhere else, so a change to the script is a case in the check. The
`kit` job runs it on a runner of its own, since it and
`scripts/systemd-check.sh` each want a machine with no relay on it; by hand
it wants a throwaway host or a VM — Docker Desktop's systemd cannot hand a
credential to a `User=` service, and the guide's own check fails there the
same way. The relay a kit carries must be a static build (`CGO_ENABLED=0`,
which `make relay-linux` sets), since the kit refuses a dynamically linked
one and a default Linux build with a C compiler present is one.

## Git

**Never commit build output.** A 9.8MB binary and an `.idea/` directory were
committed once and had to be purged with `reflog expire` and `gc --prune`.
`bin/` is ignored; keep it that way, and look at `git status` before staging.

**No author or attribution trailers on commit messages.** No
`Co-Authored-By:`, no session links, no "generated with" footers. A message
ends with its last paragraph of prose. The project's use of AI is stated once,
in the README, because it is a fact about the project and not about each
change.

**Commit messages are one sentence, in the project's voice, saying what
changed and why.** Read the existing ones. No body, no bullet list, no
trailers. The reasoning that does not fit belongs in
`reviews/IMPLEMENTATION_NOTES.md`, where it can be as long as it needs to be.

**The specifications are not in the repository.** `reviews/` is git-ignored.
Do not commit anything from it, and do not write anything there except
`IMPLEMENTATION_NOTES.md`.

## Documentation

**When you change a flag, a command, a default or a response code, the README
changes in the same commit.** A mechanical check caught five stale places
after the admin work: the build section named two binaries, the plan's layout
listing omitted three packages, an example log line had its fields in the
wrong order. Compare the README's tables against the code, not against your
memory of the code.

**Do not overclaim in the security model.** The README said the relay "cannot
build a social graph from what it stores". True of the database, false of the
process: posting is authenticated, so the relay knows the verified sender and
the target mailbox at that moment, and the default access log recorded both.
The claim was corrected and `access_log: "minimal"` was added. Every sentence
in the security model must be checkable against the code.

**Package doc comments go stale too.** After the admin work three of them still
said the relay enforces "one policy". Grep for the old phrasing when the
truth changes.

**Pin a key, not a certificate and never a serial.** A trust anchor is
identified by the SHA-256 of its `SubjectPublicKeyInfo`, everywhere: in an
enrolment token, in `config.json`, in the `certs` table. A serial is chosen by
its issuer, and a self-signed root chooses its own, so an attacker mints one
with any serial they like — it is not a binding at all. A certificate's hash
is a binding but a brittle one: re-issuing the same key with a later expiry
would invalidate every token and every pinned machine. The key is the thing
that does not change.

**A relying party must be sent every certificate between the leaf and what it
holds.** The relay holds only the trust anchor of a client's chain, and a
client holds only the trust anchor of the relay's; each must therefore send
the intermediates. The relay omitting its signing intermediate from what it
served was invisible on the relay — it started, it logged, it answered — and
fatal to every client, which got "unknown authority" with nothing to go on.
An end-to-end run found it and `TestTheServedChainReachesTheAnchor` now pins
it. Verify a chain the way the far end will, with only what the far end will
have.

**A test that searches an encoded structure must decode it first.** The test
proving a bundle withholds the offline keys compared raw DER against JSON, in
which every certificate is base64 — so it could never have failed, and it was
counted as passing for a week. Any test whose whole job is to assert an
absence should first assert it can find something that is present.

**httptest.StartTLS gives the server a certificate of its own when
`Certificates` is empty**, and with no SNI — which is what connecting to an IP
address means — `crypto/tls` prefers it to `GetCertificate`. A test that means
to serve a particular leaf must put it in `Certificates`, or it will quietly
test the wrong certificate.

**A name constraint restricts only its own kind of name.** A CA permitted
some DNS names and given no IP constraint may sign for any IP address, and
the reverse: RFC 5280 says an absent kind is unconstrained, and Go's verifier
agrees. A server intermediate that is supposed to sign for one relay must
therefore exclude outright whichever kind it has no host of. The first
version did not, and the test that should have caught it used mixed hosts,
so both kinds were constrained and nothing was open. Test a constraint with
the kind of name it does *not* list.

**A loader that verifies everything it is given will refuse the file on the
day something in it expires.** A retired intermediate in a bundle verifies
nothing once expired, but verifying it anyway made the relay refuse to
restart a year after a rotation. Anything carried for compatibility must be
tolerated once stale, not enforced. A test for this needs time to pass, so
build the fixture in the past rather than wait.

**A file that is there and wrong is not a file that is missing.** `CertFor`
answered "no certificate" for a `cert.json` that named another relay, so
`dialNoRenew` dialled without one, and the relay's refusal of a certificate
it never saw — "not accepted: run 'auu register --token TOKEN'" — was the
only word said, about a file sitting right there. Every reader of a file
that can be present and wrong tells the two apart: `ErrNoCert` is the
missing file alone, `ErrCertForAnotherRelay` names the file, the relay it
was issued by and the command for this one, and a file nothing can read is
damaged. A caller that swallows every error but success on the way to a
network call turns a local fact into a remote mystery.

**A verification failure is not a certificate refusal; do not probe.** When a
request dies at the transport, the client asks the relay again with and
without its certificate to tell a refused certificate from a dead relay. But
a failure this machine's own verifier produced — the ratchet refusing an
older signing authority, an unknown anchor, an expired or wrong-host
certificate — means the relay never got to answer, so the second question
proves nothing; and the probe's transport does not run the ratchet, so it
accepted exactly what had just been refused, and a replayed authority was
reported as "the relay refused this machine's certificate" with a new token
as the remedy. `verificationFailure` now stops the diagnostic before it
starts, and the test proves it with a probe transport that fails the test
if dialled — not by inferring from the answer that no probe was needed.

**A gate written in terms of the feature that introduced a thing outlives
that feature's ownership of it.** The trust anchor route was gated on client
certificates being required, because when it was written the anchor existed
only then. The offline CA made the anchor exist on its own, the gate stayed,
and the shipped settings — client certificates off — told every machine there
was nothing to pin, so none could connect. When something stops belonging to
one feature, find every check written in that feature's terms and name the
condition for what it is: the route now asks whether there is an anchor and
whether this relay terminates TLS, which is all it ever meant.

**Fetch and check before you write.** `auu init --anchor` generated and saved
the identity and then fetched the anchor; a wrong hash, or a relay that could
not serve one, left a new identity and nothing pinned, and the administrator's
line on the relay was dead. A command that can fail on something remote does
that part first and writes once everything has succeeded, so an error leaves
the home as it was.

**A one-way move of somebody's files writes the thing that says it happened
last, and every step before it is safe to repeat.** Moving a home from one
relay to `relays/<name>/` renames three files, writes a record, and only then
rewrites `config.json`, whose old fields are what say the move has not
happened. Crash anywhere before the last step and the home still looks
unmigrated, so the next open finishes it; each step checks for its own result
first, so finishing is not doing it twice. And move the files rather than
re-encoding them: a pinned anchor that comes out of a migration with different
bytes is a different file to reason about at exactly the moment somebody is
least able to check it, so the test compares them byte for byte.

**Do not declare a field for a migration to read on a struct that is written
back.** `store.Config` no longer has `relay`, `trust_anchor_spki` and the
rest; the migration reads them through a private struct of its own, which
makes writing `Config` back the thing that removes them, and leaves no field
for a later caller to reach for by accident. The first attempt kept them on
`Config` marked "do not add a caller" — and `time.Time` ignores `omitempty`,
so the zeroed field was written out again anyway and the migration test
caught it.

**A state marker must be written by the thing that makes it true, not by a
side effect that usually follows.** "Is this identity registered on that
relay" is recorded by a cursor file, which was only ever written when a
message arrived. A mailbox somebody had joined and never received anything
in therefore looked unjoined — and `auu inbox`, which drains every relay
with a cursor, skipped it. Registration writes it now, and so does a
successful drain, so the state repairs itself. It was found by migrating a
real home, not by a test; the tests came after.

**A check made "again inside the transaction" has to be handed the value to
check.** `RegisterOptions.TokenUse` was documented as re-verified beside
`uses_left`, and `redeem` did compare it — when it was non-empty, and nothing
ever set it, so the second check had never run. When a field exists so a
check can be repeated, look for the line that fills it; the test is that the
repeat refuses something.
