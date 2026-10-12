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
is the easy one: `Envelope.V` is outside the ciphertext, so version 3 can lay
the plaintext out as `inner || signature` and a reader knows which to expect
before decrypting. Version 2 is taken, by a message with a critical section,
which a reader from before sections refuses unopened, and the inner record
carries the version too, under the signature, which the outer one must equal. The stream is the hard one: its version is *inside* the
sealed manifest, which a reader cannot find until it has split chunk 0, so no
manifest version can say where the split is, and the manifest's version 2 is
a manifest with sections. A new layout is a new stream format under a new
info string, which is the lever `stream.go` names for any incompatible
change. The stream also fixes `EncSize`, read before anything that could
carry a version, so a suite with a different KEM needs the same new format.

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
sixteen megabytes accepted and buffered before the relay found nothing to
check them against. The signature cannot come first: it is over the body,
so the body must be read to check it; that is the one check that belongs
after the body, and the reason the body is read at all before the caller is
known to be who they say. The cost of the new order is a mailbox lookup for
a stranger before the body instead of after it — the same read, earlier,
bounded by the in-flight cap as it was. The test declares sixteen megabytes
under an unknown fingerprint, sends none of them, and is answered. The
admin routes are the one exception to the order: they read the body before
the identity is looked up, under `FramingAllowance`, a body of no declared
length refused `411` and one declared over the cap `413`, since the third
trace found that a body judged after the lookup, or waited for only under
an administrator's fingerprint, told an outsider who administers the relay.
On all three wrappers that read a body before its signature,
`authedWithCert`, `callerAuthedBody` and `adminAuthed`, a body refused
before the signature, for its length or a read that failed, is charged to
the address's unauthenticated budget as a refused signature is, so the
refusal is not a free question about which fingerprints the relay knows.
And a refusal before the body closes the connection behind its answer,
every one of them — the `413`, the `401`, the in-flight `503` — because
`net/http`, before it writes a response on a connection it will keep, reads
up to 256 KiB of a body the handler did not, and waits for one that never
comes: the first cut of this order left the in-flight cap's test flaking, a
stalled request that lost the race for the slot getting its `503` only when
the test closed the connection, since the server was waiting for the 3990
bytes it would never send before writing it. `unread` is the mark, set at
the top of every authenticated route and taken off once the body is read; a
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

**An id that selects state names the party who may select it.** `auu serve`
took an ask's thread from the message alone, and `auu send --thread` takes
any id of a message id's shape. A thread id is no secret: every
co-recipient of a message to several sees it, and so does anyone shown a
`wait --thread` line. So any peer the expert answered who knew another
peer's thread could send on it, and serve ran the handler in the opener's
worktree with the opener's attachments, counted it as the thread's next
turn, sent that peer the patch of everything produced for the opener, and
spent the opener's `max_turns`. Every check had passed — the signature was
the peer's own, the peer was admitted, the id had its shape — and none had
asked whose thread it was. Now every ledger entry records its message's
verified sender, `from`, with its arrival on this machine, the record's
`Arrived`, and the relay's counter, written once and never rewritten (an
entry an earlier release wrote holds the relay's `received` under the
same key, and keeps it); a thread's opener is the sender of its earliest
entry that is not skipped and names a sender, earliest by arrival and not
by `Tried`, since `Tried` is rewritten at every attempt and a
stream held for a newer auu has none. `channelFor` asks whose thread it is
before anything else is done with the message: one on the thread from
anybody else belongs to no channel here, is said once per message per run
(`sayOtherParty`), and is left in the inbox, unanswered, uncounted, given
no worktree and no directory. Only while nothing on the thread has been
tried or answered may a message that arrived before the recorded opener's
take the thread, so no later stamp moves a thread with a conversation in
it. A v0.17.0 ledger kept no senders: its entries take theirs from their
messages still in the inbox at the run's start (`fillSenders`). A thread
with none of its messages left once took the sender of the first message
serve took up on it after the upgrade, so any peer who knew its id could
take it over; now, once anything on it was tried or answered, it is
nobody's: `channelFor` answers no message on it from anyone, the original
asker included, and says each once per run (`sayNoOpener`), leaving it in
the inbox uncounted. The rule holds for `max_turns` too: the rule below,
that a fault a message chose is its own, keyed the count on the thread the
ledger sent its reply on rather than one the sender named; but a limit
keyed on a thread holds only as far as the thread is one party's, and it
is now keyed on a thread only its opener can add turns to. The trace's
test is `TestAThreadIsAnsweredForThePeerWhoOpenedIt`.

## The relay stays dumb

**Return stored bytes verbatim.** The relay used to re-parse each envelope on
the read path and silently skip any that failed. A row that failed could never
be delivered, never be acknowledged, and sat in the database forever. It now
hands back what it stored and the client decides; undecodable bytes are
surfaced as a nil envelope so the client acknowledges and clears them.

**A relay resolves the first name of an address and no other.** A bang path is
`bar!baz!bob`, and every name in it is what the relay *reading* it calls the
next hop. So a relay strips the first element, looks that one up in its own
courier home, and passes the rest along untouched; it never resolves `baz`,
never learns what `baz` means to `bar`, and never rewrites what it forwards.
The names are not a namespace and nothing publishes them: a relay calls each
neighbour whatever its operator chose, and what a relay calls itself appears
nowhere. A change that made a relay look past the first element would be
inventing a global namespace the protocol does not have, and would make one
operator's naming somebody else's business.

**The address rule is one function and both ends run it.**
`store.CheckAddress`, with `store.ValidRelayName` inside it: every name a relay
name, no relay named twice, and at most the cap it is given. The client runs it
before sealing and every relay runs it after appending its own name, which is
what makes a repeated name evidence of a relay that did not run it rather than a
coincidence. The cap is a parameter for the one reason worth remembering: a
relay refuses above its own `courier.max_hops`, nothing on the wire carries that
number, so a client can hold an address only to the protocol's 32 and an address
between the two passes at the terminal and is refused at the first hop in that
hop's words. The rule could not live in `relayapi`, which already holds
`MaxHops`, because `ValidRelayName` calls `channels.WindowsDevice` and
`channels` imports `relayapi`; that is a cycle, and moving the name rule instead
would have moved two dozen call sites to reach one of them.

**A courier is an identity, not a capability.** A relay forwards by being a
*user* of the relay it forwards to: it enrols there, gets a mailbox and a
certificate, and posts like anybody else. There is no privileged path and no
shared secret between operators. Two consequences a change must not break.
Everything that bounds a poster bounds a courier, which is why its quotas come
from the same helper with a different number rather than from a second
comparison beside the first. And a courier has an ordinary mailbox at its
neighbour, which nothing reads and which the relay therefore refuses every
sender into — in the words every refused sender gets, so that the refusal is not
a way to ask which relays this one peers with. That refusal is the relay's own
rule and runs before any allow document, which is testable and tested: a courier
that pushes a list admitting somebody is still refused.

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

**The allow list has one exception, and the owner signs for it.** A knock
reaches a mailbox from a sender the owner has not admitted, and it does so
only where the owner's card, verified against their registered key at that
moment and never read from the column the relay parsed at the push, says
`knocks`. It is a route of its own, `POST /v1/mailbox/{fp}/knock`, with a
cap of its own, so everything that can be judged without the body still is;
`MayPost` is never called there, and the card is never read on the post
route. The relay says one sentence for no card, a card that says no and a
card that does not verify alike, since the state of somebody else's card
is not a stranger's to learn, and the fault line for a card that does not
verify is the allow list's shape: the mailbox alone, once a minute, under
both access-log modes. What a knock buys its sender is one sealed line in
the other person's quarantine; nothing on the receiving side is trusted by
its arrival, and the name a knock carries is its sender's own claim,
offered at a prompt and never taken as a label until a person accepts it.

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
keeps the signed directory to serve it back verbatim, and the name and the
period a post is checked against come out of that document, verified
against the mailbox's registered key at the post itself. Policy the relay
enforces for a user is verified where it is enforced, which is the rule the
allow list and the card already followed: the relay also unpacks the
directory into rows at the push, but those are the administrator's count
and the watch's issue time, and routing does not read them, so an edit to
them changes what an operator is shown and not what the relay does. A
directory that does not verify closes the mailbox: every name is refused,
default and the owner's own post included, and the relay says so once a
minute in its own log, naming the mailbox. It fails closed rather than
falling back to default, since falling back would open a name the owner's
own document may have removed or closed, and since a broken allow list
already refuses every sender to a mailbox — malformed authentication data
has no state here that means "not yet". The owner is told by the word on
their listing and by what auu inbox prints, and their push is the repair.

**Nothing on the wire is from before, and one door is for what comes
after.** v0.15.0 is the floor: everything was upgraded to it once,
together, and nothing from before it is supported, so every tolerance for
an older peer is a path nobody tests and a place a wrong answer hides. A
field an end always sends has no `omitempty` and is required by the other
end, refused by name when it is absent, with nothing of the answer used:
`queued`, `allow`, and each row's `kind` (one of `envelope`, `stream` and
`knock`, a fourth refused by name) and `channel` on a listing, `created`
on a lookup, `registration` and `client_certs` on the status answer,
`max_bytes`, `knock_max_bytes` and `wire_level` on health, and `code` on
every refusal; a stubs listing whose row carries an envelope is a relay
that ignored the parameter, refused the same way. A count whose zero is a
value the relay sends, `queued`, stays an `int64`: absent and zero are one
number, and the code that runs for it is the code that runs for a real
zero. Neither end carries a branch for an older peer. Before the floor a
client read absence as a relay from before the field and filed by the
sealed record, defaulted `kind` to envelope, or said nothing; the
client's `kind == ""` read as envelope, its `ChannelKnown` filing by the
sealed record, the allow list's plain array sent beside the document for
a relay that read the array, the `ccxt1` token and the `ccx1` export line
still read — each went, and the fake old relay with them. A plain refusal
that tells a person what happened may stay as a sentence: the legacy
token header's `400`, the allow request with no document's `400`, the
`ccxt1` and `ccx1` refusals that say what to do; a tolerance that changes
behaviour goes. The fields a sender may leave out — the outer `ch`, the
inner `channel`, the manifest's, the open-stream request's — are the
other rule: absent means `default`, the sender's own word, and a message
for `default` carries no name. Keep the two apart: one is about what an
end always sends, the other about what a sender may leave out, and a
test marshals the zero value to prove the tag. What comes after the floor
does not come as a tolerance: a newer build says what an older one does
not understand through the one door below, which an older one was built
to read, so "no field but the declared ones" holds because `sections` is
one of them.

**There is one door, and it is `sections`.** Every answer body and every
request body embeds `relayapi.Sections`, and no row inside a list does
(R3): a fact about a row is never critical, because a critical section on
a page refuses the whole page, and a page one newer row refuses is a
mailbox that does not drain on that machine. A post and a knock are not
requests in this sense: their body is the outer envelope, which gains
nothing (see the next rule), so a fact a
relay needs about a post comes from a number the client holds itself to,
read from the health answer as `max-recipients` is, or from a route of
its own under a new wire level. The design for messages to several first
assumed a post carried sections and put the recipient list on it; a
v0.15.0 relay would have refused the fifth field, and the pre-read
caught it against `server.go` before a line was written. Read a body's
type before you plan to put something in it. Everything from the wire is
read through `wire.Decode`, so a field nobody declared is refused by name,
and a body's sections are held to `wire.CheckBody` at both ends: the
list's shape, then 16 KiB as this build encodes them, then the sort, a
section this build does not know ignored and one marked critical refusing
the body by its name. A sealed message and a stream's manifest carry
sections under their signature, and a section is sorted only once that
signature has verified (R7), so that nothing unsigned is ever kept as
needing a newer build or puts "update auu" in front of a person. A request
to a relay is sorted where its body was always decoded, after the request's
signature on every route that has one and before it on registration,
where the key is in the body: there the relay keeps nothing and advises
nobody, and the one thing it tells an unauthenticated caller, its wire
level, the health answer tells everyone. Two walks hold the door's reach:
one over `relayapi`, which fails on a body without it and a row with it,
and one over the relay's source, which fails on any decode of a request
outside `decodeRequest`.

**The outer envelope is four fields, for good, and a relay carries any
version of it.** `v`, `to`, `ct` and `ch`, read strictly on the post, knock
and forward routes, `v` any integer from 1 up. What a version means is
between the sender and the recipient: the forward route used to refuse an
envelope whose version was not its own, so a relay on the path that had
not been upgraded would have bounced newer mail for a matter that was not
its own. The bytes a relay stores and hands on are the bytes it was given.

**A grant document changes by its format version, never through the
door.** A token, an allow list, a card, a channel directory and a vouch
stay strict: a `sections` field under a good signature is refused, and
each has a test that says so (`TestATokenCarriesNoSections` and its four
siblings). A change to one is a new format version read beside the old,
and a writer uses the oldest that says what it means. A document whose
meaning grants something is not a place for a reader to skip what it does
not understand.

**The relay says what it can do as a wire level.** `wire_level` on the
health answer is a whole number, 1 from v0.15.0, that rises when a release
gives the relay something a client may depend on, and never falls. A
client keeps it and refuses a health answer without it; nothing compares
it yet, and the first feature that depends on a relay's ability reads it
and says "this relay is too old for that" before it tries.

**A known section's data is read strictly, and a change to it is a new
section name, never a field added to the old.** The door is lenient about
a section a reader does not know and strict about one it does: a reader
that knows the name decodes its data through `wire.Decode` under the
section's own rule, its size before the decode, and refuses what it does
not expect, a field the data does not have among it
(`TestTheRuleTakesAListAndRefusesWhatBreaksIt`). So what a name says, it
says for good, and `wire.known` is one namespace in which each name says
one thing. A name is known on the paths its feature reads it on,
registered with those paths through `wire.Register`, and held to
`wire.MaxKeptBytes` as an unknown one is on every other, though a
critical one is never refused as needing a newer auu, since whether a
name needs one does not depend on the path: `recipient-count` is
registered for requests alone and `max-recipients` for answers alone, so
on a sealed message each is kept only up to `wire.MaxKeptBytes` and
dropped and counted over it, as a name this build never heard of is. The
design for messages to several reached for one name three times: the
sealed list, a list on the request for the relay's cap, and the relay's
number on the health answer, all `recipients`. A list on a forward
request would also have told the first relay who on other relays
had been written to, which it learns from nothing else, when all it
needs is how many. They became three names with one shape each:
`recipients` for the sealed list, `recipient-count` (`{"n": N}`) on a
request, and `max-recipients` (`{"max": N}`) on the health and status
answers, `recipients.Name`, `recipients.CountName` and
`recipients.MaxName`.

**A section is critical only when reading without it would mislead.**
Critical means a reader that does not know the section must not read the
rest, so it is for a part whose absence makes the message say something
false. `recipients`, the first known section, is not critical: without
it a message to several reads truly as a message from the sender to the
reader, and a reply reaches the sender, which is a correct message with
less said. Made critical, it would have raised the envelope to
`VersionCritical`, and every message to several would have been one a
v0.15.0 machine keeps as `newer`, or leaves waiting on the relay when it
is a stream, unread until that machine upgraded, for the sake of a list
it could do without. Ask what an older reader would
believe without the part, and mark it critical only when the answer is
something untrue.

**A relay setting a client must know travels in a health section after
the floor, never in a new required field.** A client reads the health
answer strictly, so a field a v0.15.0 client does not know is one it
refuses by name, and a field a newer client requires is one it refuses a
v0.15.0 relay's answer for lacking. Either would have made the release
an upgrade in an order. `max_recipients` is said as the `max-recipients`
section on the health answer and on the administrator's status answer;
a client that knows it holds the number to its rule (1 to 32, refused as
malformed outside it, never clamped) and reads its absence as a relay
that holds no setting, so the protocol's ceiling binds; a client that
does not know it ignores it. The fields a health answer requires were
all in place at the floor, `wire_level` the last of them, added when
everything was upgraded together; after it, none is added.

**A client decides on a refusal's code and status, never its sentence.**
Every refusal is `{"error", "code"}`, the code always written, empty for a
refusal of no particular kind and shaped like a section's name otherwise.
A fixed sentence and its code are one `relayapi.Refusal` value the relay
writes whole, so a change to the words cannot part them; a sentence that
carries a value is written with its code beside it at its one site; a
refusal about a time carries it in `at`, and a client shows that time and
never reads one out of a sentence. A code a client does not know is shown
as the relay's sentence and acted on no further, so a later release adds
codes freely; a refusal no client may act on without understanding it is
a critical section, not a code. The error body's fields are frozen after
`code` and `at`: a later one goes in a section. The failure that taught
it: the certificate classifier matched fragments of the relay's words, so
a certificate refused for a reason that happened to say "has expired"
would have been read as an expired one, and every 507 that was not the
relay's own was read as a full mailbox. A walk over the client, `auu` and
the commands refuses a comparison with a refusal's sentence, a `strings`
function given one, and a sentence handed to anything but what shows it;
another holds that every code is written by some route; and each code has
a test through a real relay that fails if the relay writes the sentence
without it.

**Nothing on this machine is from before a rule.** A file from before a
rule stays refused as written, and every tolerance for one would be a
path nobody tests. Only a version before v0.15.0 can have written such a
file, since a rule added from v0.15.0 on holds only what the release
that adds it writes: a home v0.14.0 wrote is read as it is unless one of
its files breaks a rule. The other direction is kept: a file v0.15.0 or
later wrote is read by every later build, since v0.15.0 is the first
version whose files are kept, so a change to a kept file's shape adds
what it needs in a way the older file still reads. The outbox's second
kind, a copy of a message to several, is told by the sealed file beside
the record, `.stream` or `.env`, and never by a new required key, which
would have made every record v0.15.0 left waiting broken on the first
run after the upgrade; `TestARecordV0150WroteIsStillAStream` reads a
record in v0.15.0's exact keys, and `TestLimitPendingRecordShapes` holds
each kind to what this program writes for it. The rule runs one way: an
earlier build need not read a later build's file. A file from before a
rule is refused by name with a sentence saying what to do — re-create
it, delete it — never migrated and never read under the old rule. The
relay's database is the one exception, and it has a floor: from schema
11 it is carried forward, and from before 11 refused (see "Storage"); a
home's `config.json` of the shape from before a home could know more
than one relay, and a relay's file loose in the home's root, are refused
at `Open`, and `Config` is a strict decode that refuses a key it does
not write; a spool record names its relay and is held at `Load` to every
rule `Open` held it to; an outbox record without its relay is broken; a
ledger entry that counts an attempt with no time is refused; an `auu-ca`
key file that is a plain `PRIVATE KEY` block is refused, as is a relay
record without `bundle_path`. Each refusal has its test, the file made
in its old form. The tolerances that went — the home's move to
`relays/`, the relay's seven migrations, `legacyWarning` and the
first-time encryption of an authority, the empty relay name read as the
default, the sweep's "entry from before there were timestamps" — each
carried a lesson worth keeping, and those stay below in the past tense:
they are about a migration that no longer exists, but what they taught
about ordering a one-way move, a struct written back, and a state marker
is general. The terminal escapers stay, as the last line under a rule
and not the rule.

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
an `in_reply_to` are held to a message id's shape (a thread id is not its
first message's id: a new thread is given one of its own), one predicate in
`message` that the envelope, the manifest, the store, `send` and `serve`
all run; and the eight things the network names that become a path — a
fingerprint, an upload id, a token id, an attachment name, a channel name,
a relay host, a message id, a thread id — each have one rule at one named
point, walked by one table test that a new such place gets its row in first
(for an attachment name the rule is `message.SafeName` at the write rather
than a refusal, since a receiver never depends on the sender's name, and
the sender is held to its fixed point). A rule must run on both paths: the
manifest's body was never opened as an envelope's is, and a rule that held
for a small message was a door for a large one until `Manifest.Validate`
ran the same predicate.

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
messages that were fine. A worktree that is no longer a git worktree of the
channel's checkout is serve's to mend and not the run's to stop on: a
handler can do that to it, and ending the run there let one `rm -f .git`
stop the expert for every asker, so serve removes what stands at the path
under the serve root, makes the worktree again from the checkout's `HEAD`
and says so, and a git that cannot be run still ends the run. And a limit
keyed on a string the sender chose is not a limit: `max_turns` counted
answers by the thread id in the follow-up, so a peer renaming the thread on
each reply was on turn one every time; a reply is answered on the thread
the ledger sent its reply on, and a reply that names another is nobody's
here.

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

**A configuration block that does nothing is refused, not ignored.** The
`courier` block has two halves and they are independent: `home` is the directory
of neighbours this relay dials, and `authorized_file` is the list of couriers it
accepts from. One without the other is a one-way peering, which is a thing an
operator may want — a relay that receives but cannot reply, or sends but hears
nothing back — so neither is required. A block with *neither* is refused at
startup by name, because it is configuration somebody wrote expecting an effect
and it has none. The start also says which names appear in one half and not the
other, since nothing can enforce that an operator used one name in both and a
mismatch is otherwise undetectable until somebody's reply will not route.

**A default lives in the library, and it is checked against the decision that
set it, not only against its copy.** The drift test compares the command's
defaults to the library's field by field, which proves the two agree and says
nothing about whether either is the number that was decided.
`courier.reports_per_minute` shipped at 600 where the plan said 60 — not a
mistyped figure but one reasoned out from how fast a backlog drains by somebody
who never checked it against a settled question, with a comment arguing for it.
A default that has a reason should have that reason tested as a relationship
rather than as a literal: the test that now holds it says reporting is a tenth
of posting and checks the two durations the guide quotes, so changing either
number fails it and asks whether the ratio was meant to go too.

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

**A worker that waits on a timer needs the waiting injected, and the loop
needs an exit outside it.** The queue's workers wait for the next turn on a
function the relay hands them, so a test drives one without sleeping — a
test that sleeps is slow when it passes and flaky when it does not — and
that function returns early when the relay is stopping. Making it a
function is where the bug was: the `select` it replaced had the `return`
in it, and a loop whose only exit was inside the thing it called spun on a
cancelled context instead of ending, which a stop then waited on for ever.
The test that found it was not a test of stopping; it was every test that
built a relay with a neighbour, because the fixture stops the workers as
soon as it has built one — every such test hung before its first line ran,
which is a better place to find this than a cleanup, where a hang looks
like the suite being slow. Put the exit in the loop, after the wait, where
it can be seen.

**Housekeeping never waits on a sender.** The upload purge runs inside an
unrelated caller's request, every hundredth, and it took each expired
upload's lock as an abort does — the lock an append holds across the
body copy by design — so one sender dribbling an append to an expired
upload parked every hundredth request on the relay for as long as the
read timeout let the dribble go on, slot held and answer unsent. The
purge uses `TryLock`, skips what is held, says how many it skipped, and
meets them next time; and the routes themselves refuse an expired upload
with 410 and abort it, so nothing waits on the purge to end a reservation
that a sender keeps touching. Since the purge passes over a held upload,
the attempt holding it must end on its own: a reservation lives only as
long as it is fed.

**Counters, not aggregates, and adjust them in the same transaction as the
row.** Per-mailbox and relay-wide queued totals are columns updated inside
`Put`, `Delete`, `Deregister` and `PurgeMailbox`. Never `SUM` the messages
table on a hot path. `OpenStore` reconciles the counters from the messages
table every time and reports how many were wrong, so a crash between two
statements self-heals; that reconciliation is a backstop, not the mechanism.

**A database from the first kept version on is carried forward, a step
per version; below it, or above this build's, it is refused.** `PRAGMA
user_version` is the contract, and it has three answers. A version above
this build's is refused as written by a newer release. A version from
`firstKeptVersion` (11) up to `schemaVersion` is carried forward: a copy
of the database is kept beside it first, created empty, exclusive and 0600
and then filled by `VACUUM INTO` with the path bound, and without the copy
nothing moves; a copy already at that path is refused, never replaced,
since the plan's first thought, that one there was left by an attempt
that did not finish, was wrong for an operator who went back to the
release before and came forward again; then one step per version, each
the DDL that version added, frozen as a literal, run in its own
transaction with the version written inside it, so a database is always at
some whole version and a failed step leaves it at the one before. Any
other version — below the floor, or zero with tables in it, which is a
database from before the version was recorded — is refused with the
sentence naming the file and the message directory beside it and saying to
delete both, since a new database beside old mail is the lost database the
next start refuses over. The rule turned twice, and both turns are worth
keeping. Migrations were dropped when the wire's rule reached the files:
every released version was retracted, so a database at an older version
was one nobody ran, and each migration was a path nobody tested. The
failure that taught it was found before the migrations went: the plan that
took the schema from 6 to 7 wrote `preMigrations[7]`, and code that
followed the plan would have refused to open a version 6 database, wanting
a migration from 6 that was not there; a pre-migration's idempotence, its
`CREATE TABLE IF NOT EXISTS` from the shared constant, each was a rule
about code that only a database from before exercised. They came back,
with a floor, when a relay was running from before: the production relay
was at 11 when the branch above it wrote 12 and then 13, and deleting its
database would have made every enrolled machine enrol again. What the
first set of migrations got wrong is what the second is built against. A
step is never the shared table constant, since the constant is today's
table: a step to 12 that ran `carriedTable` would have created the column
13 adds, and the step to 13 would have failed on a duplicate. The old
schema a test builds from is pasted from git into
`internal/relay/schemahistory`, never derived from the tree, since a text
derived from today's tables builds today's database and calls it an old
one. And the steps are held to the constant by comparison, not by sharing
a string: a database carried from each kept version has, table for table
and index for index, the shape of a fresh one, so a step that drifts and a
constant changed without a step fail the same test. Raising the floor is
one number and the steps below it removed.

**An index or a column added to a table constant is a schema change, and
a schema change is a new version with a step.** The table constants say
`CREATE … IF NOT EXISTS`, which reads as though a file that exists would
pick up whatever the constant gains; it never does, since a file that
exists is never created again. `outbound_purge` went into the outbound
constant at e8ca901 and `outbound_share` at 766a345, both while the schema
stayed 12, so a version 12 file had three, four or five indexes on that
table by the build that made it, and nothing said which. The step to 13
carries the one tolerance in the steps for it, `IF NOT EXISTS` on those two
indexes, with the commits named beside it. A change to any table
constant bumps `schemaVersion`, adds its step and its `schemahistory`
text, and the carried-forward test is what fails when one of the three is
forgotten.

**A row that does not verify says nothing about when the owner issued
it.** A signed document replaces a row that does not verify — its
signature blanked, a bit of it flipped, its document edited, by somebody
with the database open — whatever that row's `issued` says, and the
newer-issued rule holds only between two documents the owner signed, so
the store verifies the stored row inside the transaction before its
issue time can bar a push, and the time it holds the push to is the one
inside the verified document, never the `issued` column, which the
signature does not cover and which is written for the administrator's
eye alone. This began as the rule for rows the migration
from before signed lists converted, whose issue time was the migration's
clock: had the 409 rule applied to them, an owner whose machine clock
ran behind the relay's could never have pushed over one. The first cut
read a blank signature alone as no bar and honoured any other row's
`issued` column, so an editor who flipped a bit and moved the column a
day ahead had the owner's repair answered `409 … from another machine of
yours` while `auu inbox` said to push — a loop with no exit for the
owner — and a column alone moved a century ahead under a row that still
verified barred every push with no `broken` state to name a repair at
all. The card's second reader found the first in the card's copy of the
code, which the allow list turned out to share, and the allow list's
reader found the second in both; the directory's push had never verified
the stored row at all and was made the same shape after. The rule is one
shape in three functions, `SetDirectory`, `SetAllowlist` and `SetCard`,
each with the same five rows in the test of its push.

**Do not store what the relay does not need.** There is deliberately no
column recording which token created which mailbox. That link appears once in
the operator's audit log and nowhere in the database: a permanent table of who
invited whom is a social graph of a different kind. The same reasoning is why
the relay stores no sender on a message. Two rows are exceptions, and each
carries its sender only for as long as it is itself: an upload's row, since
only its sender may append to it and somebody must be charged the
reservation, and a knock's, since the knocker's fingerprint is what lets a
second knock from one key replace the first — which is what makes
`max_knocks_waiting` a count of knockers rather than of knocks, so one
identity cannot fill a mailbox's share of it. Both go with the row: an
upload's when it completes or is abandoned, a knock's when the owner's
fetch acknowledges it, when it is replaced, or when the mailbox goes. An
owner who wants neither kept pushes a card that says no knocks. A third
was added when a relay learned to carry mail to a neighbouring relay, and
it was added by answering the same question: the outbound row names
whoever posted the envelope, because a relay cannot seal a bounce and
should not gain the ability to, so mail that cannot be delivered has to be
somebody's for anybody to be told about it; what it buys the poster is a
listing that says where their mail is, and what takes it away is the
neighbour taking the envelope — the file and the recipient go at that
moment, the poster's name outlasting them only until the window a report
could arrive in has passed. A relay with no courier configuration holds
none of it. Adding a fourth means answering the question again.

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
sender at once, and is replaced by the owner's next push. When the
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
constant for. The one exception is allowlisted in the test by site and
reason: the `PRAGMA user_version = %d` write, because a PRAGMA takes no
placeholder and the operand is the schema version the store owns. A
`LIKE` takes
its pattern as a parameter too, and the value's own rule is what keeps
`%` and `_` out of it (a short id is hex before it is a prefix). A test
parses the tree for those calls and fails on a query argument that is
not a constant expression, so a `Sprintf` into a query text is refused
by CI, whatever it formats.

## Signatures and tokens

**One identity key signs eight things, so each has its own domain string.**
`ccx-http-v1` for requests, `ccx-sig-v1` for messages, `ccx-token-v1` for
enrolment tokens, `ccx-stream-sig-v1` for a stream's manifest,
`ccx-channels-v1` for a mailbox's channel directory, `ccx-allow-v1` for its
allow list, `ccx-card-v1` for its card, `ccx-vouch-v1` for a vouch, one
peer's word that it holds another. There is a test that a signature
over the same bytes in one domain does not verify in another, in both
directions. Add a ninth thing to sign and you add a ninth domain and
a ninth test.

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
| `ccx-http-v1` + a method and path in the receive set: `GET` of a listing, a blob, an allow list, a card, a directory or certs; `DELETE` of a message; `HEAD` of an upload; `POST` of this identity's certs, which is renewal | receive |
| `ccx-http-v1` + anything else — a post, an upload, a push, a registration, an admin route | send |
| `ccx-sig-v1`, `ccx-stream-sig-v1`, `ccx-channels-v1`, `ccx-allow-v1`, `ccx-card-v1`, `ccx-vouch-v1`, `ccx-token-v1` | send |
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

**A service holds its identity key in the clear, and its account locks it
away.** A program that sends with nobody there cannot type a passphrase,
and no agent a person unlocked is waiting for it. So a service's key is a
plain identity file. The account the service runs as, that account's
directory and the unit that starts it are what keep the key from everyone
but root. The relay's courier was built on a plain identity file before the
guide said a service may hold one. This paragraph makes it the rule, so
that the next service does not decide it again.

The tree has two such services:

- The relay's courier home, named by `courier.home` and set up with no
  passphrase (`docs/relay.md` 1.10, the passage beginning "Set the home
  up as the user the relay runs as"). `openHome` in
  `internal/relay/courier.go` refuses one whose identity is encrypted, by
  name. The relay uses it only to dial a neighbour. Accepting forwarded
  mail through `courier.authorized_file` needs no identity key, so a
  relay that dials nobody holds no identity key.
- An expert on a dedicated account (`docs/creating-experts.md`), whose
  every reply originates.

A person's own account running `auu serve` is the other shape. The key
stays encrypted. `auu unlock --send --ttl 0` and `auu agent start` after
each boot put it in the agent in send scope, and a user unit with
lingering keeps serve running (`docs/serve.md`). Serve's refusal under
receive scope, in the paragraph above, belongs to this shape alone: a home
in the clear has no agent and no scope, and `cmdServe` in
`internal/auu/serve.go` asks for send scope only when the home is
encrypted.

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
but eighteen constants deliberately still say `ccx` — the thirteen `ccx-*-v1`
strings (`ccx-allow-v1`, `ccx-card-v1`, `ccx-carried-v1`,
`ccx-channels-v1`, `ccx-chunk-v1`, `ccx-envelope-v1`, `ccx-http-v1`,
`ccx-id-v1`, `ccx-sig-v1`, `ccx-stream-sig-v1`, `ccx-stream-v1`,
`ccx-token-v1`, `ccx-vouch-v1`: eight under a signature, three in an HPKE `info` or a
chunk's additional data, one under the fingerprint hash, and one over an
envelope a relay is carrying), the `ccx1` and `ccx2` export-line
prefixes, the `ccxt1` (read) and `ccxt2` (written) token prefixes, and the
`X-CCX-Auth` header. Recount with `grep -rn '"ccx' --include='*.go'
internal cmd | grep -v _test` when you add one; run on 2026-10-01 when the
vouch's domain went in, it answered nineteen lines: the seventeen
lower-case constants, the agent's second spelling of the request domain,
and one comment quoting the export prefix, with the header, in upper
case, the eighteenth constant the grep does not match.

`ccx-carried-v1` is the one of the thirteen that is not on any wire.
A relay's carried table is its own — no two relays compare hashes, and
nothing about one ever leaves the process that made it — so what the
domain buys is not agreement between ends but separation from every other
hash this tree makes, which is the same reason each signed thing has one.
Renaming it would cost a relay the memory of what it has already carried,
once, and nothing else; it is in this list because a future reader
grepping for `ccx` should find it with an answer beside it rather than a
question. Every one
of them is either inside a signature, inside an HPKE `info` string, or in a
format two machines have already agreed on. Renaming any of them invalidates every
identity, message and token in existence and silently breaks compatibility with
any deployed relay. If a future rename tempts you, rename the commands and
leave the wire alone. When a format does have to change, do what `ccx2` did: a
new prefix, the old one still read, only the new one written. One of the
thirteen is spelt a second time, in `internal/agent/scope.go`, where the agent
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
`inline_max`, `max_bytes` held to `relayapi.MaxPageBytes`, 64 MiB, plus
`FramingAllowance`; the knock at `knock_max_bytes`, or `max_bytes` when
that is unset, either held to `inline_max`, plus `FramingAllowance`;
`/v1/forward` at `inline_max` plus `FramingAllowance`; `/v1/forward/failed`
at `MaxReportBytes`; two of the three owner-signed documents at
`MaxDocumentBytes`; and every other body route at `FramingAllowance` alone,
the card among them, since a card at its maximum is a few hundred bytes —
with a body that declares itself over the cap refused `413` before a byte,
naming the cap. **A signed document has a cap of its own, and it is not the
body's**: `MaxDirectoryBytes`, `MaxAllowlistBytes` and `MaxCardBytes` bound
the bytes the owner signed, each measured from a document at every maximum
as this client marshals it compact with room above for a signer that
indents, each written in the constant's comment, and each run **before the
signature** — at the push, at every reading of a stored document, and by
the client before it sends one — since a length is the one check that costs
nothing and tells the caller nothing. Without them a registered identity
pads a document with whitespace to the route's cap and every reader
verifies the padding: the relay on every post, and an administrator's page
on every mailbox in it. A document over its cap is not verified, which for
a stored row means it reads as broken and fails closed like any other
document that does not verify; and HTTP/2 is off on the
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
acknowledge — is bounded at the relay to `max_bytes` of envelopes, never
above `relayapi.MaxPageBytes`, the first admitted whatever its size so a
page is never empty, and held at the client to twice the relay's
`max_bytes` plus `FramingAllowance`, learned from the health answer,
which carries it always, and never above `relayapi.MaxListingHold`, a
page over a hold already there asked for again with half as many rows,
down to one, before it is refused (the rule on a range proven, below);
and the stream routes, whose length is the transfer's, run with no
whole-exchange timeout and a stall rule of the relay's resume window on
both bodies, since a two-minute timeout under the one-request wire meant
a stream needing four minutes on the link could never be placed.

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

**The client follows no redirect, and builds every `http.Client` in one
place.** `relayHTTP` is the only constructor in `internal/client`, and its
`CheckRedirect` returns `http.ErrUseLastResponse`. A 3xx is therefore an
answer like any other, refused as malformed and naming its status, and
the `Location` is never fetched. A test walks the package's source and
fails on `http.Client` named anywhere outside the helper other than
behind a pointer (a literal, `new`, a declared value), on
`http.DefaultClient` and the package functions that use it (`Get`,
`Post`, `Head`, `PostForm`), on an assignment to `CheckRedirect` outside
it, and on `net/http` imported under another name, since a rule in a helper holds only where every path reaches the
helper. It does not see a copy made through a pointer (`cp := *c.http`),
and none is made. A relay API has no reason to
redirect. The signed request header is not one Go strips on a redirect
to another host, so following one would hand it to whoever the Location
named. And the sentence the client builds about a refusal names the
request it answered. Until PLAN-SECTIONS commit 5, the client followed
redirects under Go's default policy. `resp.Request` was then the last
request, whose URL the relay chose, and `url.Parse` decodes `%1b` in a
path to ESC itself. A relay answering `302` to `/%1b]0;x%07%1b[2J`, then
`404` with words this build could not read, drove the terminal through
"refused GET … in words this build cannot read". The second reader found
it before it shipped. The sentence's relay and route are escaped as well,
for whatever names a request next.

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

**A range the code proves is not a range safe for what it sizes.** The
client held a listing page to twice the relay's `max_bytes` plus
`FramingAllowance`, and the health check admits `max_bytes` up to
`MaxBytesCeiling`, a gigabyte. The integer ledger's row for it was true,
and the range was the one the code held; but a relay that said a gigabyte
once on its health answer and answered a listing with gigabytes of white
space could have an `auu serve` or `auu watch` host killed for memory by
the relay it reads. A row proves what a value may be; what the value is
multiplied into, allocated or held needs a ceiling of its own, and the
ceiling is a client constant, not the relay's word. Now `holdFor` takes the
smaller of twice `max_bytes` plus `FramingAllowance` and
`relayapi.MaxListingHold`, twice `relayapi.MaxPageBytes` plus
`FramingAllowance`, 128 MiB and 64 KiB, and a page over it is refused as
malformed naming it. The relay meets it from its side: a page's budget is
`max_bytes` held to `MaxPageBytes`, and the post, the knock, a forward and
a courier's delivery store no envelope over `inline_max`, the same
`min(max_bytes, MaxPageBytes)`, so a relay of this release builds no page
its clients refuse but for a lone row stored before the upgrade. An older
relay fills a page to its whole `max_bytes`, so `ListWait`, refused at a
hold already at `MaxListingHold`, asks again with half as many rows and the
same `after`, down to one, before the refusal stands. The trace's test is
`TestTheListingHoldIsBoundedWhateverTheRelaySays`.

**What a peer writes is held to a rule at Validate and escaped again where
it is shown, and nothing is ordered by a clock the sender set.** A
subject and a text reached the terminal as they came, and `Validate`
held the subject to a length only: a subject is one line, an attachment
name is one name, and neither carries a control, format, private-use or
separator character; text keeps a line break and a tab and nothing else
from those classes; a record read back from the spool is held to the
same rule at `Load` and refused by name if it fails, since a record
written by hand, or by a version from before the rule, is not one this
program wrote; and every print of them escapes all the same, as the last
line under the rule. The stamp inside a message is the sender's word: `FindThread`
ordered by it first, so a peer stamping year 9999 was the latest on a
thread for as long as the message was kept and drew every reply by
thread. Order by arrival here, by this machine's clock, then the
relay's counter; the relay's `received` is the relay's word and only
breaks a tie after the counter, and the stamp breaks one after that and
is displayed, labelled as the sender's. The one bound on the stamp is
the future, the same skew a request is held to, so a message may be old
but not from a clock no relay would have accepted.

**Every time from outside has a row in the limits ledger's time kind,
saying its bound or why it has none.** Compare times as times, two
bounds and no subtraction, and the one bound on a stamp is the future.
The third trace found that bound written by hand where someone had
thought of it: a message, a manifest and a vouch refused a stamp from
the future, and the allow list, the card and the channel directory,
documents an owner signs and every peer reads, took one from any year.
`internal/limits/ledger.txt` now holds to a row every field of a
`json`-tagged struct of a type that holds a time: `time.Time`, a struct
embedding one, a type defined over it, or a pointer, slice, array or map
of these, a map by its key too; and every `time.Parse` and
`time.ParseInLocation`: `<= now + 5m` with its test, a window, a
deadline, a field only displayed, an output, the program's own clock or
its user's input, or a value a check already held. A new time field
from outside lands with its row.

**Retry-After is an integer number of seconds, never a date, never zero.**
Rounded up; a zero would invite the client straight back into a refusal.

**An upload attempt is one request.** The chunked upload wire — an append
per piece, a `HEAD` for the offset, a completion — let a sender build a
stream up on the relay a piece at a time, each piece a request of its own
with its own lock, and a resume the sender could repeat without end. Under
the one-attempt wire a `PUT` carries the sealed bytes from an offset to
the end, with `Content-Length` required and equal to what is left, judged
before a byte is read; an attempt that stops short is kept only when it
was the first and reached the threshold, for sixty seconds from the moment
it stopped and one resume, and otherwise leaves nothing; and the sender
learns what the relay holds by its next attempt, never by asking. A limit
on what a request may carry is not a reason to cut the request into more
of them: the relay streams the body to disk under a hunk deadline, so the
request's length is the stream's. The deadline runs `relayapi.HunkWindow`
from the attempt's start and is set that far on from the read that
completes a whole hunk, `relayapi.HunkBytes`, since it last moved, and an
opened upload no attempt has started on goes at `relayapi.StartWindow`. A
deadline that every delivering read moved let a sender trickle a byte a
window and hold the reservation for ever, out of reach of every expiry and
of the purge, which passes over an attempt in flight.

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
The documents tell a person what to type, and a command or a relay flag
renamed in the code would leave every document that names it wrong with
nothing failing. `TestEveryDocumentCommandExists` beside it reads the
README, `docs/*.md` and `docs/releases/*.md` with the same reader, which
splits a line at `;`, `&&`, `||`, `|` and `$(`. It also reads a form behind
`$ `, `sudo` and its options, `env`, a variable set in front
(`AUU_HOME=/x auu`), `ExecStart=` or a bin directory. In `cmd/auu-relay`,
`TestEveryDocumentRelayFlagExists` holds every `auu-relay` form in the same
documents, a line ending in `\` joined to the next, to the flags
`registerFlags` builds. `TestTheRelayFlagTableMatchesTheFlagSet` holds the
flag table in `docs/relay.md` section 1 to that set both ways. None of the
three has an exemption: a release note that names a removed command as
history gets one when it is needed, with its reason.

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
guard against a commit made by habit, which such a spelling never is. A
substitution is read as the commands it runs wherever sh would run it: in
a word, inside double quotes, in the body of a here-document whose
delimiter is unquoted (`cat <<EOF` expands `$( )` there; `cat <<'EOF'`
does not, and its body stays text), and inside a backtick substitution's
own text, where sh strips the backslash from an escaped backtick before it
runs the text, so `` echo `echo \`git commit -m x\`` `` is the commit it
is — the two forms the gate read past until the plan after the ultra
review, each found by the worker while fixing the review's finding. A
commit whose message comes from a substitution, `git commit -m "$(cat
msg)"`, runs that substitution before the commit and is refused for it:
`git commit -F <file>` is the way to give a message from a file, and a
here-document with a quoted delimiter the way to give one inline.

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
last, and every step before it is safe to repeat.** The home's move from
one relay to `relays/<name>/`, which went when nothing on this machine was
from before any more, renamed three files, wrote a record, and only then
rewrote `config.json`, whose old fields were what said the move had not
happened. A crash anywhere before the last step left a home that still
looked unmoved, so the next open finished it; each step checked for its
own result first, so finishing was not doing it twice. And it moved the
files rather than re-encoding them: a pinned anchor that comes out of a
move with different bytes is a different file to reason about at exactly
the moment somebody is least able to check it, so the test compared them
byte for byte. The rule outlives the move: any one-way change to
somebody's files is ordered the same way.

**Do not declare a field for a migration to read on a struct that is written
back.** `store.Config` has no `relay`, `trust_anchor_spki` and the rest; the
home's move read them through a private struct of its own, which made
writing `Config` back the thing that removed them, and left no field for a
later caller to reach for by accident. The first attempt kept them on
`Config` marked "do not add a caller" — and `time.Time` ignores `omitempty`,
so the zeroed field was written out again anyway and the test caught it.
Today `Config` is a strict decode and those keys are refused by name, which
is the same rule from the other side: a field that is not on the struct is
not read, and a key that is not written is not accepted.

**A state marker must be written by the thing that makes it true, not by a
side effect that usually follows.** "Is this identity registered on that
relay" is recorded by a cursor file, which was only ever written when a
message arrived. A mailbox somebody had joined and never received anything
in therefore looked unjoined — and `auu inbox`, which drains every relay
with a cursor, skipped it. Registration writes it now, and so does a
successful drain, so the state repairs itself. It was found by moving a
real home to `relays/`, when the move existed, not by a test; the tests
came after.

**A check made "again inside the transaction" has to be handed the value to
check.** `RegisterOptions.TokenUse` was documented as re-verified beside
`uses_left`, and `redeem` did compare it — when it was non-empty, and nothing
ever set it, so the second check had never run. When a field exists so a
check can be repeated, look for the line that fills it; the test is that the
repeat refuses something.
