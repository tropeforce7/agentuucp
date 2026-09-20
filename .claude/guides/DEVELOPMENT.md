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

**Pin what Go would negotiate.** The client's transport set `MinVersion`
1.3 and nothing else, the anchor fetch set no minimum at all, and the
relay's certificate-files branch allowed 1.2; nobody set
`CurvePreferences`, so Go negotiated, and a peer offering only X25519 got
X25519 — which the security model then described as a fallback, and an
outside reader rightly called a downgrade at the transport. Every
`tls.Config` the project builds now pins `MinVersion` to 1.3 and
`CurvePreferences` to `X25519MLKEM768` alone, through one function on the
client side and one literal on the relay's, with no option to relax it:
every relay is built from this tree, so there is nothing older to be
compatible with, and a knob would be a downgrade somebody could turn. The
client turns the refusal into a sentence naming the relay, since Go's is
"remote error: tls: handshake failure". A setting the library would choose
for you is a setting you have chosen by omission; write it down, and test
the refusal from both sides.

And test it through the public constructor, not the helper. The pin lived
in `transportFor`, and `NewWithAnchor` called it only when it had a
certificate or an anchor to add; with neither — a relay with a public
certificate and no client certificates, which is also `auu-admin`'s path
to such a relay — the `http.Client` kept a nil `Transport`, which is
`http.DefaultTransport` and Go's handshake, TLS 1.2 and any curve. The
v0.7.0 regression test built its client through `transportFor` and so
proved the helper and not the path; an outside reader found the gap three
releases later. A pin in a helper is a pin only where every path reaches
the helper: the constructor now always builds its transport through it,
and `TestThePinHoldsWithNoCertificateAndNoAnchor` builds the client with
nothing to add and asserts the refusal and the negotiated hybrid. When a
test reaches for an internal helper to prove a property of the public
thing, that is the sign it is proving the wrong one.

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

**Everything that can be judged without the body is judged before it,
and the signature after it.** On every authenticated route the order is
the certificate, the auth header parsed, the identity it names looked up,
then the body under the route's cap, then the signature over it. Until
PLAN-HTTP the body was read before the header was parsed, so a stranger
with a valid certificate and a fingerprint no mailbox had could have
sixteen megabytes accepted and buffered before the relay found nothing
to check them against. The signature cannot come first: it is over the
body, so the body must be read to check it; that is the one check that
belongs after the body, and the reason the body is read at all before
the caller is known to be who they say. The cost of the new order is a
mailbox lookup for a stranger before the body instead of after it — the
same read, earlier, bounded by the in-flight cap as it was. The test
declares sixteen megabytes under an unknown fingerprint, sends none of
them, and is answered. And a refusal before the body closes the
connection behind its answer, every one of them — the `413`, the `401`,
the in-flight `503` — because `net/http`, before it writes a response on
a connection it will keep, reads up to 256 KiB of a body the handler did
not, and waits for one that never comes: the first cut of this order
left the in-flight cap's test flaking, a stalled request that lost the
race for the slot getting its `503` only when the test closed the
connection, since the server was waiting for the 3990 bytes it would
never send before writing it. `unread` is the mark, set at the top of
every authenticated route and taken off once the body is read; a
request that declares no body keeps its connection.

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
And for adding one to a total: `OpenUpload` computed `queued + reserved +
size > quota`, which for a declared size near `MaxInt64` wrapped negative,
under any quota, and took the reservation; the row then made `SUM(size)`
overflow inside SQLite and every later open for the mailbox a storage
error. Compare with what is left instead — `size > quota - queued -
reserved`, whose terms cannot wrap — and keep a bound against `MaxInt64`
where there is no quota, so the sum the database computes next time still
fits; and cap what the wire may declare at all (`MaxStreamSize`, 2^62)
whatever a setting says, since "0 for unlimited" must still be a number.

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

**A log line limited to once a minute is keyed by the thing it is about,
never by the sentence.** The fault log says why a storage fault was
answered as a 500, once a minute per path, so a broken disk under a busy
relay does not fill the journal with one line; the allow list's "does not
verify; refusing every post" line goes through the same limiter, keyed
`allowlist:FP`, so a burst of refused posts is one line and two broken
mailboxes are two. Limit by the sentence and the second mailbox is never
mentioned; do not limit and a sender in a retry loop writes the journal.

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

**Nothing on the wire is from before.** Every released version is
retracted and no peer from before this batch is supported, so every
tolerance for one is a path nobody tests and a place a wrong answer
hides. A field an end always sends has no
`omitempty` and is required by the other end, refused by name when it is
absent, with nothing of the answer used: `queued`, `allow`, and each row's
`kind` and `channel` on a listing, `created` on a lookup, `registration`
and `client_certs` on the status answer, `max_bytes` on health; a stubs
listing whose row carries an envelope is a relay that ignored the
parameter, refused the same way. A count whose zero is a value the relay
sends, `queued`, stays an `int64`: absent and zero are one number, and
the code that runs for it is the code that runs for a real zero. Neither
end carries a branch for an older peer — the client's `kind == ""` read
as envelope, its `ChannelKnown` filing by the sealed record, the allow
list's plain array sent beside the document for a relay that read the
array, the `ccxt1` token and the `ccx1` export line still read — each
went, and the fake old relay with them. A plain refusal that tells a
person what happened may stay as a sentence: the legacy token header's
`400`, the allow request with no document's `400`, the `ccxt1` and `ccx1`
refusals that say what to do; a tolerance that changes behaviour goes.
The fields a sender may leave out — the outer `ch`, the inner `channel`,
the manifest's, the open-stream request's — are the other rule: absent
means `default`, the sender's own word, and a message for `default`
carries no name. Keep the two apart: one is about what an end always
sends, the other about what a sender may leave out, and a test marshals
the zero value to prove the tag. Local file formats are not the wire:
a home's records from before a rule, an unencrypted key file, are files
on this machine and have their own rules.

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

**What a peer names is never a path.** The second adversarial trace sent
`--thread "../../outside"` from an admitted peer, and `auu serve` joined it
onto its serve directory, wrote the message's text there, asked git for a
worktree there, and ended every round for good on the error: a thread id
was the one thing a message named that had no rule. Now a thread id and
an `in_reply_to` are message ids, one predicate in `message` that the
envelope, the manifest, the store, `send` and `serve` all run; and the
eight things the network names that become a path — a fingerprint, an
upload id, a token id, an attachment name, a channel name, a relay host,
a message id, a thread id — each have one rule at one named point, walked
by one table test that a new such place gets its row in first (for an
attachment name the rule is `message.SafeName` at the write rather than
a refusal, since a receiver never depends on the sender's name, and the
sender is held to its fixed point). A rule
must run on both paths: the manifest's body was never opened as an
envelope's is, and a rule that held for a small message was a door for a
large one until `Manifest.Validate` ran the same predicate.

**Every path a file operation takes has its provenance written down, and
one that is not the program's own has run a rule before the call.** Every
`os.Open`, `OpenFile`, `Create`, `ReadFile`, `WriteFile`, `Mkdir`,
`MkdirAll`, `Remove`, `RemoveAll`, `Rename`, `Stat`, `ReadDir`,
`CreateTemp`, `Symlink`, the path in `sql.Open` and `net.Listen`, and
every `exec.Command` whose arguments are paths, is a row in the file-open
ledger (`internal/fileopens/ledger.txt`), keyed by file, enclosing
function, callee and the argument as written, and each row says where the
path came from: *local*, made by the program from a directory it chose
and names it wrote; *operator*, in one of three forms — a whole path used
as given, a flag or a file named on the command line; a value from a
configuration file, which resolves against that file's directory and
never against the working directory, said with its base; or a name the
person chose that is joined under a directory, a relay name under
`relays/`, said with its rule and the point it runs; *derived*, made from
something the program read back from its own files or environment — an
entry of a directory it owns, held to the reader's own rule before it is
joined back, a record it wrote with the rule at the read, `os.Executable`
and the runtime directory as the environment's own; or *network*, a
component a peer or a relay sent, with the rule that ran on it and the
point where it ran, the rule a function in the tree or, for a number the
JSON decoder held to a number, the standard-library function that writes
it. A message id from the spool is *network*: it was the sender's, and
the rule that made it a name ran at open and at save. Where a path has
components of several kinds the row names the least trusted, and a
helper's row the least trusted of its callers'. The store's exported
edges run the rule again at the call — `Load`, `Save`, `Remove`,
`DamagedPath`, `SetLeftBehind`, `DefaultRelay` on the name from its own
config, `Relays` on each entry — since a caller's slip must not walk a
path out of the home. Every row that is not *local* names, after `shown
by`, the limit test that drives the traversal set through its rule, or
says why nothing is joined (the operator's whole path, the environment's
own). A test walks the tree for those calls and fails on a call with no
row, a row with no call, a key twice, rows out of order, a network row
naming a rule that does not exist, and a row that is not local and names
no test. The third review found the configuration values the second
form covers — the relay's `db` and `messages_dir`, serve's `dir`,
`key_file` and `control` — resolved against wherever the process had
started, so a settings file meant two things under a unit and a shell;
resolution against the file is the rule, and the docs say so where the
file is described. So a
new file operation is refused by CI until its path's provenance is
written down, and a path from the network cannot reach the disk without
naming the check that made it a name and not a path. The previous rule
found the eight components the network names; this one is how the ninth
is found before it is a finding.

**A fault a message chose is that message's failure, never the run's.**
`serve` treated every error out of `handle` as the host's — a disk, a
lock, a key — and ended the run, so one message with a bad thread id
stopped the expert at every start until a person removed it by hand. The
message's own fault, its thread id, is refused before the id is joined
onto anything and recorded in the ledger as its failure, and the round
goes on to the next; what is the host's — git failing, the channel's
directory gone, the disk — still ends the run, since a host fault
counted against each message would burn their retries and give up on
messages that were fine. And a limit keyed on a string the sender chose
is not a limit: `max_turns` counted answers by the thread id in the
follow-up, so a peer renaming the thread on each reply was on turn one
every time; a reply is answered on the thread the ledger sent its reply
on, and a reply that names another is nobody's here.

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

**A setting pair that cancels a guarantee is refused, not documented.**
`registration: open` beside `client_certs.mode: required` let any holder
of the identity key re-register with no token and be issued a fresh
certificate, so revoking a machine's certificate revoked nothing; the code
had a comment saying the cost was the registration mode's business, and
the adversarial trace read it as a design limitation worth a sentence in
the docs. It is refused at startup instead, in one sentence saying why,
and the kit refuses the pair before it writes a settings file. When two
settings are each fine alone and together undo what one of them is for,
`Validate` says so; a sentence in a guide is read by fewer people than a
refusal is.

**A default is a decision: the safe mode is the one that applies when
nothing is said.** The relay's `tls.mode` used to be inferred — `files`
when a bundle or a certificate was named, `off` otherwise — so `auu-relay
--listen :8080 --db relay.db` was a plain-HTTP relay without anybody having
said so, and the quick starts taught it that way. Now an empty mode is
`files`, a relay with nothing to serve TLS from refuses at startup in one
sentence naming `auu-ca init`, `auu-ca relay` and `--tls-mode off`, and
`off` exists only when written down and says so on its first lines. When
you add a mode, the value that applies to a setting nobody wrote is the
safe one, and the unsafe one has to be typed.

**`encoding/json` HTML-escapes by default.** `--print-config` rendered
`<redacted>` as `<redacted>`. Use a `json.Encoder` with
`SetEscapeHTML(false)` for anything a person reads or pastes back in, and test
that the printed form loads again.

**A struct that is printed as the config file cannot carry non-config
state.** The startup warning about file permissions is returned beside the
`Config`, not stored on it, because `Config` round-trips through
`--print-config`.

## Storage

**One SQLite connection.** `MaxOpenConns(1)` with `busy_timeout`. That means
every statement inside a transaction must go through the `*sql.Tx`; calling
`s.db` from inside an open transaction deadlocks.

**One upload's operations are serialised by a lock held across the copy,
never a transaction.** `AppendUpload` read the row, copied the body onto
the file and only then updated the row, and two appends at one offset
both passed the offset check and both landed: an admitted sender held
twice what they declared and twice what was reserved, bounded only by the
in-flight cap, and the upload could never complete. Now the store keeps a
mutex per upload in progress, taken by an attempt from the offset check
through the copy, the sync and the row's update or the file's removal
(under the one-attempt wire placement runs under it too), and by an abort
for its whole length; the entry goes with the upload. A SQLite
transaction is the wrong tool for it: one open for the length of a
network read would hold the one connection every other request needs.
Serialise with a lock what a transaction cannot span, and test it with
two callers, one parked inside the copy.

**A count against a quota is one arithmetic in one helper.** `Put` and
`OpenUpload` each compared against the same quotas with sums of their
own, and only one of them counted the other's reservations: a sender who
opened a stream for everything free could post envelopes into the
reservation and complete the stream on top, ending a mailbox and the
relay over their quotas by up to one stream. `roomFor` answers once, by
subtraction (`size > quota - queued - reserved`, never a sum that can
wrap), with the open uploads' reservations counted for an envelope as
for a stream, and both callers ask it. Two callers with two arithmetics
are a quota with a gap between them.

**Housekeeping never waits on a sender.** The upload purge runs inside an
unrelated caller's request, every hundredth, and it took each expired
upload's lock as an abort does — the lock an append holds across the
body copy by design — so one sender dribbling an append to an expired
upload parked every hundredth request on the relay for as long as the
read timeout let the dribble go on, slot held and answer unsent. The
purge uses `TryLock`, skips what is held, says how many it skipped, and
meets them next time; and the routes themselves refuse an expired upload
with 410 and abort it, so nothing waits on the purge to end a reservation
that a sender keeps touching.

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

**A migration is keyed by the version it starts from, and a pre-migration
creates what it fills.** `migrations[5]` takes a database from 5 to 6; the
plan that took it from 6 to 7 wrote `preMigrations[7]`, and code that
followed the plan would have refused to open a version 6 database, wanting
a migration from 6 that was not there. A pre-migration runs outside and
before its transaction, so the table the Go half writes into does not
exist yet: it creates it from the same constant the fresh path uses
(`CREATE TABLE IF NOT EXISTS`, so `sqlite_master` still matches) and
writes with `ON CONFLICT DO UPDATE`, and the SQL half repeats the constant
as a no-op and drops the old table. Both halves are idempotent because a
crash between them leaves the old version, and the next start runs both
again. The old migration tests built the past from the table constant;
when the constant became the new table they would have built the wrong
past, so the old DDL is written out as a literal, as every earlier
schema's is.

**A time the relay wrote orders nothing the owner did.** An unsigned allow
list converted by the migration carries the migration's clock as its
issue time; had the 409 rule applied to it, an owner whose machine clock
ran behind the relay's could never push over it. A signed document
replaces an unsigned row whatever its time, and the newer-issued rule
holds only between two documents the owner signed.

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

**Policy the relay enforces for a user is signed by that user and verified
where it is enforced, not where it was stored.** The allow list was a plain
table, `allowlist (fp, sender_fp)`, written from a JSON array the owner
sent: the one piece of a user's policy the relay held that it could not
prove came from the user, so that whoever could write the database could
admit a stranger, whose mail the relay then accepted for the mailbox. It
is now a document the owner signs, as the channel directory always was,
and `MayPost` verifies the signature against the mailbox's registered
bundle on every post, with no cache: a cache would hide an edit made while
the relay runs until it restarted, which is the edit the signature exists
to catch. An edited row therefore refuses every sender rather than
admitting one, and the owner's listing says `broken` until they push
again. Verifying at store time alone would have proved only that the row
was once the owner's. A row with no signature is broken too; the next rule
says why.

**No compatibility state for authentication data: anything malformed
fails closed.** The first signed-list release read a row with no signature
as a "legacy" list from before signing and honoured it, so that an upgrade
would lock nobody out — and so an editor who blanked a signature and
rewrote the document was refused by nothing on the relay, caught only when
the owner's own machine, remembering its push, noticed at its next fetch.
An outside reader called that what it was: a compatibility state for
authentication data, with a window in it, kept for users who did not
exist, since no relay outside the project ran before signed lists. Now a
row with no signature is broken before anything is parsed, refuses every
sender at once, and is replaced by the owner's next push; the migration
is unchanged and what it writes is read as broken, which closes a
restricted mailbox across the upgrade rather than opening it. When the
question is whether to honour authentication data that cannot be
verified, the answer is no, and a state that says "not yet" is a hole.

**A credential a program uses on behalf of untrusted input is held by a
process that input cannot reach, and what the input's process holds is a
token that dies with it.** `auu serve` runs Claude Code on mail from
strangers' agents, and the handler used to be given `ANTHROPIC_API_KEY` in
its environment: a crafted ask could have the key printed into a reply and
carried back over the relay, and in side-copy mode the model has a shell.
Now serve reads the key once, keeps it in memory, runs a reverse proxy on
loopback, and gives each invocation of the handler a base URL with a
random token in its path, live for that invocation alone; the proxy swaps
the token for the key on the way out. The token is worthless off the host
and dead after the run, so what the handler can leak is nothing. Anything
serve inherited under the credential names is dropped from every
program's environment, since a unit that still carries the key would hand
it on through serve. What one account cannot protect is said in the
guide rather than implied away: the handler is the same user as serve and
can read the key file if told where it is; the split proxy, `auu serve
proxy` as another account with a file of its own, is the answer to that,
and then the expert's file names only the control socket, so the handler
learns nothing of the key from anything it can read.

**A failed insert is only a duplicate if the row is actually there
afterwards.** `UseNonce` and `AddToken` re-query after a failed insert. Reporting
every failure as a replay or a duplicate would hide a broken database behind a
401 or a 409.

**A value reaches SQL only as a parameter, and the query text is made of
constants.** Every `Query`, `QueryRow`, `Exec` and `Prepare` in the tree
takes its text from string constants, joined by `+` where a clause is
optional (`certRows`, `Tokens`), and every value goes in `args`, `?` for
`?`, and a parameter that carries a query is one every caller passes a
constant for. The exceptions are three, allowlisted in the test by site
and reason: the two `PRAGMA user_version = %d` writes, because a PRAGMA
takes no placeholder and the operand is the schema version the store
owns; and the migration's statements, chosen from the `migrations` map
by the version the store read from itself, each a `+` of the schema
constants. A `LIKE` takes
its pattern as a parameter too, and the value's own rule is what keeps
`%` and `_` out of it (a short id is hex before it is a prefix). A test
parses the tree for those calls and fails on a query argument that is
not a constant expression, so a `Sprintf` into a query text is refused
by CI, whatever it formats.

## Signatures and tokens

**One identity key signs six things, so each has its own domain string.**
`ccx-http-v1` for requests, `ccx-sig-v1` for messages, `ccx-token-v1` for
enrolment tokens, `ccx-stream-sig-v1` for a stream's manifest,
`ccx-channels-v1` for a mailbox's channel directory, `ccx-allow-v1` for its
allow list. There is a test that a signature over the same bytes in one
domain does not verify in another, in both directions. Add a seventh thing
to sign and you add a seventh domain and a seventh test.

**The agent decides by the domain it is asked to sign under, never by who
asks.** The second outside review's closing point: key extraction was
defended and key misuse was not, because any process running as the user
can have the unlocked agent sign, and content that subverts an AI can make
it originate as the person. No in-band confirmation helps, since the same
process answers it. So an unlock has a scope (`internal/agent/scope.go`):
receive, the default, and send, for `auu unlock --send` with the passphrase
again and ten minutes by default. The agent classifies each operation from
what it is asked to sign, and the domain strings above are what make that
possible without a protocol change — which is a second reason every signed
thing has one at the front. The table:

| asked to sign | scope |
|---|---|
| `ccx-http-v1` + a method and path in the receive set: `GET` of a listing, a blob, an allow list, a directory or certs; `DELETE` of a message; `HEAD` of an upload; `POST` of this identity's certs, which is renewal | receive |
| `ccx-http-v1` + anything else — a post, an upload, a push, a registration, an admin route | send |
| `ccx-sig-v1`, `ccx-stream-sig-v1`, `ccx-channels-v1`, `ccx-allow-v1`, `ccx-token-v1` | send |
| anything else under the identity key, malformed included | send |
| a machine key (`cert:`, `pending:`): the TLS handshake, a CSR | receive |
| `generate` under a `cert:` name, a new machine key for renewal, or for enrolment before `POST /v1/register` makes it send | receive |
| `generate` under any other name | send |

Renewal is receive because it is maintenance of this machine's transport
credential and not an act of the person: the relay issues the certificate
to the fingerprint of the identity that signed the request and to no other,
the request must arrive on the live certificate it then retires, it carries
no token and enrols no machine, and the new key never leaves the agent.
Without that row a home in receive scope — the default — would be warned
for the last sixty days and then lose its certificate. The health check
and the key lookup are in no row because the client does not sign them:
the relay verifies no signature on either (`handleHealth` reads no header;
`handleKeys` checks the certificate and the unauthenticated limiter and
reads none), so a signature there bought nothing and put the caller's
fingerprint in a full-mode access log on a route that did not need it —
on the lookup, a route about somebody else. `client.verifiedRoute` is the
list; the relay cross-check walks those routes too and expects send, since
a signing string for one is not the client's. Sign only what the other
end verifies.

Unknown is send, always; over-strict is the right side, because a wrong
receive costs a signature and a wrong send costs a retry.
`TestTheClassifierAgreesWithTheRelay` in `internal/relay` walks every route
the relay registers against this table, so a route added without a row
fails. Add a signed thing, or a route, and you decide its scope on purpose.
The client surfaces a refusal as exit 4 with the agent's sentence verbatim,
and `auu serve` — the one thing that originates unattended by design —
refuses to start under receive scope in its own words.

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
`auu`, `auu-relay`, `auu-admin` and `auu-ca`, and the project is AgentUUCP,
but fifteen constants deliberately still say `ccx` — the ten `ccx-*-v1`
domain strings (`ccx-allow-v1`, `ccx-channels-v1`, `ccx-chunk-v1`,
`ccx-envelope-v1`, `ccx-http-v1`, `ccx-id-v1`, `ccx-sig-v1`,
`ccx-stream-sig-v1`, `ccx-stream-v1`, `ccx-token-v1`: six under a
signature, three in an HPKE `info` or a chunk's additional data, one under
the fingerprint hash), the `ccx1` and `ccx2` export-line prefixes, the
`ccxt1` (read) and `ccxt2` (written) token prefixes, and the `X-CCX-Auth`
header. Recount with `grep -rn '"ccx' --include='*.go' internal cmd | grep
-v _test` when you add one. Every one
of them is either inside a signature, inside an HPKE `info` string, or in a
format two machines have already agreed on. Renaming any of them invalidates every
identity, message and token in existence and silently breaks compatibility with
any deployed relay. If a future rename tempts you, rename the commands and
leave the wire alone. When a format does have to change, do what `ccx2` did: a
new prefix, the old one still read, only the new one written. One of the
nine is spelt a second time, in `internal/agent/scope.go`, where the agent
recognises a relay request by its domain without importing `relayapi`;
`TestTheClassifierAgreesWithTheRelay` is what fails if the two ever differ.

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

**The HTTP layer's bounds are written down, and there is one protocol.**
The maintainer asked how the relay limits a header and a body, and the answer was
that Go's defaults did: a megabyte of headers, a body cap of `max_bytes`
plus the framing allowance on every route including the ones whose
requests fit in a kilobyte, and HTTP/2 offered by ALPN on the listener
while the client, having cloned `http.DefaultTransport`, forced it — so
every deployed exchange ran over a protocol no test in the tree ran,
`httptest` speaking HTTP/1.1 unless told otherwise. Now the request line
and headers are capped at `relayapi.MaxHeaderBytes`, which `net/http`
answers `431` before any handler (through 4 KiB of its own read-ahead, so
the cut lands at the cap plus 4096, and the test says so); an auth header
is held to `relayapi.MaxAuthHeader`, the length its five fields can
reach, before a field is cut from it; every body is read under its
route's cap, `readBody` taking the cap as an argument — the post route at
`max_bytes` plus `FramingAllowance`, the two owner-signed documents at
`MaxDocumentBytes`, sized to their maxima as the client marshals them
(the document is base64 inside the envelope, so 4/3 of it, measured and
written in the constant's comment), and every other body route at
`FramingAllowance` alone — with a body that declares itself over the cap
refused `413` before a byte, naming the cap; and HTTP/2 is off on the
relay's listener, `TLSNextProto` an empty map and `NextProtos` http/1.1
alone, so the drain, `Connection: close` and the stall deadline are
proven under the protocol that is deployed. A cap is the plainest bound
there is: name it as a constant, refuse before the body where the body
declares itself, and test the edge and one past it from a raw connection
that sends the headers and nothing more. The client's side is the same
rule read the other way: its transports offer http/1.1 alone and cap a
response's headers at the wire constant; every JSON answer is read
under a hold, and the one answer that grows with a relay's setting — a
listing page, which had no byte bound at all, up to 200 envelopes of
`max_bytes` each, a page nobody could hold and so a mailbox nobody could
acknowledge — is bounded at the relay to `max_bytes` of envelopes, the
first admitted whatever its size so a page is never empty, and held at
the client to twice the relay's `max_bytes`, learned from
the health answer, which carries it always; and the stream routes, whose
length is the transfer's, run with no whole-exchange timeout and a stall
rule of the relay's own window on both bodies, since a two-minute
timeout under the one-request wire meant a stream needing four minutes
on the link could never be placed.

**Every byte from the network is escaped before a terminal sees it, and the
relay's sentences are from the network.** `identity.Printable`'s comment
promised that every place a name from the network reaches a terminal goes
through it, and three did not: `auu-admin`'s confirmation before it
removes a mailbox printed the relay's name raw at the one moment an
administrator is reading carefully; a certificate label dropped control
characters alone, so a bidi override reversed the rest of a listing's
line; and the sentence a relay attaches to every refusal, which every
user of every relay reads on standard error, was printed as it came. The
escaper runs where the value is made, not where it is printed —
`HTTPError` escapes the sentence in its one constructor, so no caller can
forget — and a name, a label and a sentence each have a form:
`Printable` for a name with a rule, `PrintableText` for a sentence (space
and tab kept, quotes and backslashes too), `PrintableLines` for prose.

**A string from the network is never sliced before its rule has run.**
`m.FP[:16]`, `cert.Serial[:16]`, `t.ID[:12]` and `t.Subject[:8]` in
`auu-admin` and `auu` sliced fingerprints, serials and token ids straight
out of a relay's JSON, and a Go slice past the end of a string is a
panic: a relay that answered a two-byte fingerprint crashed the tool. The
client checks every id-shaped field of every answer type in one place
per type as it comes off the wire, refuses an answer that fails whole as
malformed, naming the field and the relay, and the command slices what
it was given. The same holds for a number: bounded before it is
multiplied or allocated from, the way `retryAfter` clamps `Retry-After`
before `time.Second` — the agent's unlock TTL was not, and a multiple of
2^55 seconds wrapped to exactly zero, which unlock read as until lock.

**What a peer writes is held to a rule at Validate and escaped again where
it is shown, and nothing is ordered by a clock the sender set.** A
subject and a text reached the terminal as they came, and `Validate`
held the subject to a length only: a subject is one line, an attachment
name is one name, and neither carries a control, format, private-use or
separator character; text keeps a line break and a tab and nothing else
from those classes; and every print of them escapes all the same,
because a record from before the rule, or written by hand, is still in
the spool. The stamp inside a message is the sender's word: `FindThread`
ordered by it first, so a peer stamping year 9999 was the latest on a
thread for as long as the message was kept and drew every reply by
thread. Order by arrival here, then the relay's counter, and use the
stamp to break a tie and to display, labelled as the sender's; the one
bound on it is the future, the same skew a request is held to, so a
message may be old but not from a clock no relay would have accepted.

**Retry-After is an integer number of seconds, never a date, never zero.**
Rounded up; a zero would invite the client straight back into a refusal.

**An upload attempt is one request.** The chunked upload wire — an append
per piece, a `HEAD` for the offset, a completion — let a sender build a
stream up on the relay a piece at a time, each piece a request of its own
with its own lock, and a resume the sender could repeat without end. Under
the one-attempt wire a `PUT` carries the sealed bytes from an offset to
the end, with `Content-Length` required and equal to what is left, judged
before a byte is read; an attempt that stops short is kept only when it
was the first and reached the threshold, for sixty seconds from the
moment it stopped and one resume, and otherwise leaves nothing; and the
sender learns what the relay holds by its next attempt, never by asking.
A limit on what a request may carry is not a reason to cut the request
into more of them: the relay streams the body to disk under a stall
deadline that every delivering read moves, so the request's length is the
stream's.

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

## Processes, accounts and the shell

**Windows builds its own command line.** `exec.Command("cmd", "/c", line)`
quotes the line the way `CommandLineToArgvW` unquotes it, and cmd.exe is
os/exec's documented exception: it unquotes differently, so an exec line
that opens with a quoted path — every line naming a program whose path
might hold a space — reaches cmd quoted again and does not run. Resolve
cmd.exe with `exec.Command("cmd")` and set `SysProcAttr.CmdLine` to
`cmd /S /C "LINE"`: `/S` strips exactly the outer pair of quotes and leaves
the rest as written. A `GOOS=windows` vet proves it compiles; the Windows
job is what proved it runs.

**Killing a tree is the process group on Unix and `taskkill /T /F` on
Windows.** There is no process group to signal on Windows, so killing the
shell left the handler under it running and holding the file its stderr
was going to, and the test's directory could not be removed. Walk the tree
with `taskkill /T /F /PID`, and fall back to killing the one process where
`taskkill` is not there to be run. Nothing a program serve starts may
outlive its timeout on either platform, and the documentation says so
without "on Unix".

**A tool you assume is on every Linux host is not, until a bare image says
so.** `uuidgen` is not on Debian 13: it is in `uuid-runtime`, which nothing
installs by default and which util-linux does not carry, so the wrapper as
the plan drew it would have died at the first message of every new session
with `uuidgen: not found` — and there `set -e` does end the script, since
the assignment is a plain command. The wrapper tries `uuidgen`, falls back
to `/proc/sys/kernel/random/uuid`, which is on every Linux machine, and
refuses by name when there is neither. A `debian:13-slim` container is
where this was found, and the install check runs in `ubuntu:24.04` with
nothing on it for the same reason.

**Give git a setting for one command through `GIT_CONFIG_COUNT`, never
`--global`.** A checkout somebody else owns — root building in a user's
tree, a user building in one root unpacked — is what git calls dubious
ownership and refuses to read, and `go install` then cannot stamp the
version. The install script names that one directory safe for that one
command with `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory
GIT_CONFIG_VALUE_0=$PWD`; nothing is written to a config file, and nothing
is left in the environment. The private-repository token travelled to git
the same way while there was one. And a version string with a `+` in it is
a pattern to `grep -E`: compare versions with `grep -F`.

**A caller admitted to a group to reach a socket is in the group that reads
what the socket guards.** The split proxy's socket is 0660, and the first
draft of its guide, and the first run of row S11, put the expert's account
in the proxy's group to let it connect — the group that may read the key
file, which is the whole of what the split proxy exists to prevent; the
row's first assertion, `sudo -u auu-expert cat /etc/auu-proxy/key`
failing, is what caught it. The socket takes the callers' group, never the
holder's: the proxy is put in that group by its unit's
`SupplementaryGroups=` so that it may give the socket and its directory
away with `chown`, and it refuses to start, naming that line, when it
cannot. Two lines admit a caller, the file mode and the kernel's account of
its uid and groups, and neither touches the key.

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

**What a program needs beside it to be used is carried in the program.**
The three Claude Code skills reached a machine only through `make
install-skill`, which copies files out of a checkout; a person who
installed with `scripts/install.sh` or `go install` — nearly everyone — had
the binaries and no skills, and a checkout for three files is a source of
trouble. They are embedded now (`skill/embed.go`, a package with nothing in
it but bytes, since an embed directive reaches only at or below its
package), `auu skill install` writes them out, the install script runs
that for an ordinary user, and the copy on a machine is the one that
matches the `auu` beside it. Two tests close the loop: the embed test
proves the binary's bytes are the tree's, the dispatch test proves the
tree's forms dispatch. A person's edited file is kept and named, never
overwritten in silence, since the file is theirs once written.

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

**No commit without the rules review.** Every one of the rules in these two
guides was learned from a fault that shipped, and a change that reads well
can still put one back: a number multiplied before it is bounded, a name
sliced before its rule has run, a path made from a string the network chose.
So after `git add` and before `git commit` the change is read against the
guides by the `rules-review` skill, which writes a record under
`.git/rules-review/` naming each rule the change touches, the line, and the
test that shows the value. The hook in `.claude/hooks/rules-gate.sh` refuses
a commit with no record for the staged diff, or one that does not say ready.
The record is the answer to "what did you check", and it is written before
anyone has to ask. The gate reads the command as sh does and does not
expand, so a command word or a git subcommand it cannot read as a literal
word — a variable, or a word a `$( )` or a backtick is part of — is
refused rather than guessed: the ultra review found `x=commit; git $x`
and `git $(echo commit)` passing as "not a commit", and the gate is a
guard against a commit made by habit, which such a spelling never is.

**The specifications are not in the repository.** `reviews/` is git-ignored.
Do not commit anything from it, and do not write anything there except
`IMPLEMENTATION_NOTES.md`.

## Documentation

**When you change a flag, a command, a default or a response code, the README
or the document under `docs/` that describes it changes in the same commit.** A mechanical check caught five stale places
after the admin work: the build section named two binaries, the plan's layout
listing omitted three packages, an example log line had its fields in the
wrong order. Compare the documents' tables against the code, not against your
memory of the code.

**A document that moves breaks every link to it, and a test keeps them
resolving.** When the README was broken up into `docs/client.md`,
`docs/relay.md` and `docs/security.md`, every anchor in every document
changed with the section numbers, two tests that read the README for the
exit-code table went with the table, and a grep for "README" was the only
thing that found them. `TestEveryDocumentLinkResolves` at the module root
now walks every Markdown file in the tree and fails on a relative link or
`#anchor` that does not resolve to a file or a heading, by GitHub's slug;
it is part of `make test`. Move a section and the test says which link you
forgot, by document and line.

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
