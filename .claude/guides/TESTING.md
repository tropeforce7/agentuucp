# Testing guide

For an agent, or a person, contributing to this project. The rules come from
tests that were wrong, tests that were missing, and tests that passed for the
wrong reason. Read `DEVELOPMENT.md` beside this file first.

The bar is: `make vet test build` clean, `make race` clean, and every
test the specification lists exists under a name a reviewer can find with
grep. The specifications are in `reviews/`, git-ignored; ask if it is empty.

## What a test is for

**A test proves the check exists, not that the code compiles.** The envelope
tests build a hostile envelope by hand for the signature-and-bundle-mismatch
case so that check is exercised rather than assumed. Every security ordering
rule in `DEVELOPMENT.md` has a test that would fail if the order were
reversed. If you add a check, add the test that fails without it, and confirm
it fails by reverting the check once.

**A test of what happens after a step must get past the step.** The test
that a locked agent never gets a message discarded first locked the agent
and called `fetch`, and passed with the discard rule deleted — the request
signature failed before any message was fetched, so the code under test was
never reached. It now signs locally and decapsulates through the agent,
which is the shape of a TTL expiring between a signed request and the
message it fetched, and fails with the rule deleted. When a test is about
the second failure, arrange for the first thing to succeed, and break the
rule once to see that the test reaches it.

**Assert the refusal and the absence of side effects.** A 403 is half a test.
The enrolment refusal cases assert three things: the status, the message, and
that no mailbox was created and no token lost a use. `assertNoTokenSpent`
tells a use a test spent deliberately from one a refusal leaked by looking at
`last_redeemed`. The unauthenticated-nonce test counts nonce rows before and
after. Count the rows.

**Assert the exact message when an operator or a user will read it.** Error
text that names the limit, the setting, or the file is part of the interface.
`errorText(t, body)` exists for this; use it rather than matching on the raw
body.

**When a test fails, decide whether the test or the code is wrong before
touching either.** Two examples from this project. A test asserted that a
spent token could not enrol "a second time" and failed because the second run
was the same identity re-registering, which needs no token and is correct; the
test was wrong. Another asserted the admin mailbox listing "leaked message
content" by searching the body for the word `queued`, which matched the field
name `queued_messages`; the test was wrong. Neither was a code bug, and either
fix to the code would have been a regression.

**A claim about another program's behaviour is run against that program,
not believed.** Two examples. The wrapper's `[ -n "$AUU_ATTACHMENTS" ]
&& prompt=…` line was reported as a bug under `set -e` that would end the
script before `claude` ran; running it on `/bin/sh` here and on dash in a
`debian:13-slim` container showed the opposite — POSIX exempts a failing
command in an AND-OR list unless it is the script's last line — and the
report was retracted before anything was changed for it. The same plan
rested on Claude Code accepting `ANTHROPIC_BASE_URL` on loopback with a
path and a key that does not begin `sk-ant`, and that was proved against
the real binary with a fake upstream on 127.0.0.1 before the pre-read went
back, which also found the `HEAD /api/hello` probe and the tool-search
warning nobody had guessed at. If the claim is about a shell, a container
or another program, the test is to run it there; a sentence in a note is
not one.

## Adversarial input

Three rules for unit tests of anything that checks a value, transforms data,
or verifies integrity. They are cheap to follow and they catch the class of
bug that survives every other kind of test.

**Test both sides of every boundary, one step apart.** For a check of the
form `lo <= x <= hi`, the test values are `lo-1`, `lo`, `hi` and `hi+1`: two
refused, two accepted. Testing only `hi+1` lets a `>=` written for `>` pass,
because the wrong comparison still refuses the value one past the edge; it is
the value *on* the edge that tells them apart. This applies to every
integer-like parameter — sizes, counts, uses, list limits, byte budgets,
durations — and to timestamps, where a window has two edges and a skew
allowance moves both, so there are four values to hit. `MaxUses` is 1000: a
token with 1000 uses must issue and one with 1001 must not, and *both* belong
in the test — `MaxUses+1` alone was the gap this rule was written for. The
project's tests do this in
`TestUsesAndNoteBoundaries`, `TestFreshAtBoundaries`, `TestMaxBytesBoundaries`,
`TestBodyCeilingBoundary` and `TestFingerprintPrefixBoundary`; follow those.

**For signed types, also inject the type's MIN and MAX, and the inputs that
make the intermediate arithmetic land on them.** Negation, subtraction,
multiplication and bit twiddling all misbehave at the extremes, and Go does
not trap. In C an overflow is undefined behaviour; in Go it is a wrong answer
with no signal at all, which is worse for a test, because nothing crashes and
the wrong answer looks like an answer. Two examples from this codebase, both
found by writing this rule down and then checking it.

`relayapi.Auth.FreshAt` used to take an absolute value: `delta := now - ts; if
delta < 0 { delta = -delta }`. But `-math.MinInt64` is `math.MinInt64`. A
timestamp chosen so that the subtraction wraps to exactly `MinInt64` stayed
negative after negation, satisfied `delta <= skew`, and was reported fresh: a
request stamped 2^63 seconds away passed the freshness check. Neither the bare
`MinInt64` nor the bare `MaxInt64` triggers it — those happen to be rejected —
which is why the rule says *the inputs that make the arithmetic land on the
extremes*, not merely the extremes themselves. It now compares the timestamp
against `now-skew` and `now+skew` and never subtracts;
`TestFreshAtDoesNotTakeAnAbsoluteValue` fails against the old code.

`handleAdminAddToken` used to compute a token's lifetime as
`time.Duration(notAfter-notBefore) * time.Second`. Any span longer than about
292 years overflowed the multiplication into a negative `Duration`, which
compares as shorter than `token_max_age`, and the cap was bypassed. It now
compares in seconds and never converts to nanoseconds. `retryAfter` in
`internal/client` had the same shape and the same fix, clamping before the
multiplication rather than after it.

So, for every signed parameter: MIN, MAX, MIN+1, MAX-1, zero, minus one; and
for each subtraction or negation in the code under test, the input that makes
its result MIN. For unsigned: zero, MAX, and the input that makes a
subtraction wrap. For every narrowing conversion: the first value that does
not fit. Absolute value is a red flag on sight — there is no correct `abs` over
the whole range of a two's-complement integer, so write the comparison that
does not need one.

### The ways an integer goes wrong, and the value that shows each

The rule above says what to inject. This says where to look, because an
overflow is not one bug but a family, and each member has its own tell in
the code and its own value in the test. Go traps none of them: an
arithmetic overflow is a wrong number with no signal, and only a slice
index, a `make` length, a division by zero or a nil map write panics.
Every example here is from this tree, and the fix for each is in it.

**A sum of two claimed values.** `queued + size > quota` is the natural
way to write a quota and the wrong one: two non-negative operands the
peer chose can sum past `MaxInt64` into a negative, and a negative is
under any quota. That was `OpenUpload` before v0.9.0, and once the row was
in, `SUM(size)` over the table overflowed inside SQLite, which does signal
("integer overflow"), and every later open was a storage error. The
shape that cannot wrap is `size > quota - queued - reserved`: each
subtrahend is non-negative and together under the quota, so the
difference is in range. Test value: the size that makes the old sum land
exactly on `MinInt64`, and one under it; assert the refusal, then that a
second, small request is refused or taken and never a storage error.

**A difference of two values that may be either way round.** `now - ts`,
`size - offset`, `to - from + 1`: each is correct while the operands are
in the order the writer pictured. A peer picks the other order. The
freshness check took an absolute value and met `-MinInt64 == MinInt64`
(the first rule above). `to - from + 1` is a `make` length in
`readBlobRange`; both operands are this side's own there, but the same
expression with a wire operand is a panic when `to < from - 1`. Test
value: the operands reversed, and the pair that makes the difference
`MinInt64`; where the difference sizes a `make`, assert the refusal came
before it (measure `TotalAlloc`, as under Length and allocation).

**A multiplication by a unit.** Seconds to nanoseconds is a thousand
million, so anything over about 292 years of seconds wraps a
`time.Duration`. Three places in this tree had `time.Duration(n) *
time.Second` with no bound on `n`: a token's lifetime (negative, so under
the cap), `Retry-After` (fixed alongside it), and the agent's unlock TTL
(found in the sweep after the second trace). The TTL case has the tell
worth remembering: a multiple of 2^55 seconds wraps to exactly zero,
which unlock read as "until lock". A negative check after the multiply
misses it, because the wrap is not negative. Bound the operand before
the multiply, at a number a person would recognise (a year, a hundred
years), and test the bound, one over, `MaxInt64`, and the multiplier that
lands on zero: `2^64 / 10^9` has no integer solution, but `2^55 * 10^9`
is `2^64 * 5^9`, so 2^55 is that value for nanoseconds.

**A count times a size.** `chunks * chunkSize`, `uses * something`, a
loop that allocates per item. Both operands from the wire multiply to
anything. `ChunkCount` derives the count from the size and refuses a
manifest whose stated count differs, so there is one operand, not two;
the attachment total is checked against what is left of
`MaxPayloadBytes` before each add. Test value: the pair whose product
is one over the cap, and the pair whose product wraps to a small
positive.

**A narrowing conversion.** `int64` to `int` is a no-op on every platform
this project ships for, but `uint32(n)` and `uint8(n)` drop bits without
a word: 256 threads is 0 threads, and Argon2 panics on 0. `costFor`
bounds each parameter to what the narrower type holds before the cast,
and the test is the first value that does not fit: 256 for a `uint8`,
2^32 for a `uint32`. A float in a JSON number field declared `int64` is
refused by `encoding/json`; a float field converted with `int(f)` is not,
and is implementation-defined out of range. Do not declare a wire number
as float.

**An unsigned subtraction.** `n - 1` where `n` is a `uint32` length
prefix and zero is legal wraps to four billion. The agent's frame reader
checks `n == 0` and `n > MaxFrame` before anything, and its length is
never decremented. Test value: zero, and `MaxUint32`.

**A running counter that goes below zero.** `queued_bytes` and
`queued_messages` are decremented on delete and on abort. A double
delete, or an abort of a row the purge already took, would carry one
under zero, and a negative queued total is room. Every decrement is
inside the transaction that removes the row, so a row is charged off
once; the Storage section's "corrupt the counters and reopen" test is
the check that a wrong total is noticed rather than trusted. Test value:
the same delete twice, asserting the counter moved once.

**A loop bound from the wire.** `for i := 0; i <= n; i++` with `n ==
MaxInt` never ends: `i++` wraps past it. `for i := n; i >= 0; i--` with an
unsigned `i` never ends either. Bound `n` first (the count rule under
Length and allocation), and write `<`, not `<=`, against a cap the code
chose.

**A slice index or a `make` from a number.** These panic rather than
wrap, which is better and still a crash: `s[:16]` on fifteen bytes,
`make([]byte, n)` with `n` negative or over memory. The relay's answers
were sliced for display with no check until commit 7 of the second
trace's fixes, and `token.Describe` sliced a pasted token's issuer to
sixteen characters on claims `Parse` had checked nothing about, until
the integer review; an index into a unit string is the same shape, and
`humanBytes` indexed `"KMGT"[exp]` with `exp` at 4 for a pebibyte a peer
declared, so the loop that finds the unit is bounded by the units now.
The rule under What the network names covers the slice; for `make`, the
length is compared against a cap the operator chose before the call, and
the test measures that the refusal allocated nothing. Test values for a
slice of a string from outside: the empty string and one byte shorter
than the slice; for an index by magnitude, the first value past the last
unit and `MaxInt64`.

**A shift by a wire value.** `1 << n` is 0 for `n >= 64` in Go and a panic
for `n < 0`. There is none in this tree from the wire; if one is added,
test `63`, `64` and `-1`.

**A database integer.** SQLite's INTEGER is a signed 64-bit, and `SUM()`
over a column can exceed it while every row fits: that is the second half
of the quota story above. Any aggregate the code reads back is bounded by
what the code lets into the rows, and the test is the row that makes the
aggregate overflow: assert the refusal came at the insert.

**Time.** `time.Time` compares safely with `Before`, `After` and `Equal`
over its whole range; `Sub` saturates at the `Duration` limits rather than
wrapping; `Unix(sec, 0)` takes any `int64`, though not every one is
where it looks: `Unix(math.MaxInt64, 0)` overflows the shift to year 1
and lands before 1970, and the latest instant is
`Unix(math.MaxInt64-62135596800, 999999999)`. The hazards are the
conversions: a span to a `Duration` (the multiply above), a `Duration` to
an `int` of seconds, and a stamp from a peer used as an order (the second
trace's commit 9: a message stamped in the year 9999 was the latest on
its thread). And a saturated `Sub` negated: `-d` of the minimum
`Duration` is the minimum, so `token.Until` read an expiry from
centuries ago as inside the relay's skew with a negative age, until the
integer review; it compares times with `Before` now and negates nothing.
Compare times as times, bound a span in the unit it arrived in, and never
order by a clock the peer set. Test values: `time.Unix(math.MinInt64, 0)`,
the first instant at which `Sub` saturates and the one just inside it, a
year in the past, and a day and a year ahead.

For any expression with a wire operand, the recipe is the same: write
down which operands the peer chose; for each operator, the value that
lands the result on `MinInt64`, `MaxInt64`, zero or minus one; and a test
that feeds it and asserts the refusal fired before the expression, by the
error, by the order of the checks, or by the bytes allocated. The wrong
answer is silent, so the test must know where the right answer stops.

**Messages for cryptographic tests are random, and a failing test publishes
its seed.** A test that seals and opens, signs and verifies, issues and
verifies, or encodes and decodes must run over messages random in content and
in length, not a fixed string. A fixed string takes one path through the
padding, the block boundaries and the encoding; random input takes the others,
and the others are where the bug is. Force these lengths into the
distribution as well as random ones: 0, 1, the AEAD block size and one either
side of it, the maximum, and one over the maximum.

Use `testutil.Seed(t)`, which takes the seed from `AUU_TEST_SEED` if set and
from `crypto/rand` otherwise, builds a `math/rand/v2` generator, and logs the
seed at the top of the test. Go prints `t.Logf` output only for a failing test or under
`-v`, so the seed appears exactly when it is needed and never otherwise, and a
failure reproduces with `AUU_TEST_SEED=<n> go test -run <Name>`. Put the seed
in the failure message too, so it is beside the assertion that fired.

**A random generator must produce input that is valid for the thing under
test.** `TestRoundTripRandom` gave each attachment a name drawn from a thousand
candidates, and two attachments in one message collide often enough to fail
about one repeated run in three — but a message with duplicate attachment names
is *correctly* refused by `Validate`, so the test was failing on its own
invalid input rather than on the envelope it was meant to exercise. Generate
the varying parts randomly and the structural parts by construction: names by
index, ids by counter, anything with a uniqueness rule from something that
cannot collide. When a randomised test fails, read the message before assuming
the code is wrong; this one said `duplicate attachment name` and named the
rule it had broken.

Random tests are in addition to fixed known-answer vectors, never instead of
them. A known answer pins the wire format against other implementations;
random input finds the edge nobody thought of. The project does both:
`TestRoundTripRandom`, `TestSignThenVerifyRandom`, `TestIssueVerifyRandom`,
`TestSignVerifyRandom` and `TestAttachmentRandom` are randomised, and
`TestKnownAnswer` in `internal/token` pins the token format.

**Always assert the negative path, and vandalise precisely.** Every function
that verifies, opens, or decodes with integrity has a test that it fails when
it should, and "fails" means the specific error, not merely an error.
Replacing a 64-byte signature with 64 bytes of `A` proves less than it looks:
something rejected the input, which may have been a length check or a base64
decoder rather than the signature check. A single flipped bit keeps the
length, the encoding and every structural property intact, so the only thing
left to reject it is the cryptography. Flip one bit with `testutil.FlipBit`
and assert the specific failure.

Flip it in every structurally distinct region, because each region is
guarded by a different check and a flip in the last byte tests only the last
check. That means knowing the format: the offsets are named from its
constants (`ed25519.SignatureSize`, the suite's encapsulation size, the AEAD
tag size), not guessed. For an envelope the regions are the `to` field, the
KEM encapsulation at the front of `ct`, the AEAD body, the AEAD tag at the end,
and the inner Ed25519 signature — which cannot be reached by flipping
ciphertext bits at all, so it needs an envelope sealed by hand with a bad
inner signature, which is what `TestSignatureBundleMismatch` does. For a
token: the payload and the signature separately, plus the same payload under
a different key. For a request signature: method, path, body hash, timestamp
and nonce, each changed on its own, which `TestVerifyFailsOnChanges` does.

Two more vandalisms belong in every set: truncate by one byte, extend by one
byte. And two more pairings: the right message under the wrong key, and the
right key on the wrong message.

A small helper earns its keep here:

```go
// flipBit returns a copy of b with one bit inverted. i is the bit index from
// the start; callers derive it from the format's constants, never a literal.
func flipBit(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i/8] ^= 1 << (i % 8)
	return out
}
```

## Length and allocation

A length is a claim the peer makes. Every one of them — a `Content-Length`,
a base64 string, a count field, an array, a `LIMIT` parameter — is an
invitation to allocate, and an attacker will state whatever number makes you
allocate the most. The rule is that nothing is allocated in proportion to a
number the peer chose until that number has been checked against a cap the
operator chose, and the test is that a blown-out length is refused *before*
the allocation would have happened, not after.

**Bound the reader, not the buffer.** The server wraps every request body in
`http.MaxBytesReader(w, r.Body, MaxBytes+framingAllowance)`; the client reads
every response through `io.LimitReader(body, DefaultMaxBytes*2)`, because a
hostile relay does not get to exhaust a client's memory either. Never size a
buffer from `Content-Length`: it is a header, and a client can say `1<<40` and
send ten bytes. `io.ReadAll` over a bounded reader grows from 512 bytes and
stops at the cap. Tests: a body one byte over the cap is 413; a
`Content-Length` far over the cap with a small real body is refused, not
waited for; and the stalling-body pattern from the harness section, because a
declared length that never arrives is a time attack, and the bounds on time
are `ReadTimeout`, `ReadHeaderTimeout` and the in-flight cap, each of which
has its own test.

**Check the encoded length before you decode.** Base64 decodes to three
quarters of its length, hex to half, and both allocate the whole output first.
`token.Parse` and `identity.ParseExportLine` used to decode and then check the
length; they now check first, computed from the encoded size. Neither was
exploitable — a token arrives in an HTTP header, which `net/http` caps at 1
MiB, and an export line comes from a file or a pasted argument — but the shape
was wrong and would have been copied into a place where it mattered. The test
for the right order uses the "which check fired" trick: an input whose length
is over the cap *and* whose last character is not valid base64 must produce
the length error, not the decode error. If the decode error comes back, the
decode ran first.

**A count field is a loop bound and a `make` argument.** `uses` is capped at
1000, `limit` at `MaxListLimit`, and a page of mailboxes is never larger than
the limit that was asked for and capped. Any new field that says "n of the
following" gets a cap before it drives a loop, a `make`, or a transaction.
The body cap is not enough on its own: 16 MiB of 64-character fingerprints is
a quarter of a million entries, and a `PUT .../allow` with all of them was a
quarter of a million inserts in one transaction, bounded only by the
per-identity request rate. That is what `relayapi.MaxAllowlist` is for. If you add an array to the wire, add a length
cap to it, and test `cap`, `cap+1`, and `math.MaxInt` for the count.

**Measure it.** For a unit test, assert the specific error and the order the
checks fired in, as above. For anything that reads from the network, read
`runtime.MemStats.HeapAlloc` before and after handling a blown-out request
and assert the difference stays under a small multiple of the cap; a test that
only checks the status code cannot tell a refusal from a refusal that
allocated a gigabyte first. `testing.AllocsPerRun` counts allocations, not
bytes, and is the wrong tool here.

`HeapAlloc` is live bytes, so it only sees an allocation that is still held
when the reply arrives. The agent's frame test measured `HeapAlloc`, and
passed with the length check moved after the allocation: eight megabytes
were allocated, refused and garbage before the reply was read. Where the
thing under test would allocate and drop, measure `TotalAlloc`, which is
cumulative and sees every byte; with the check moved it reported 8,552,512
bytes for eight refusals.

**Nothing on the wire is compressed, and that is deliberate.** If compression
is ever added, the cap goes on the decompressed size and the reader stops at
it, or a kilobyte of input becomes gigabytes of output.

**Truncate before you log.** A string from the wire that reaches a log line
or an error message is bounded first. The token note is capped at 200 bytes
and re-validated on the relay; a `reason` on a block is validated with the
same function; the access log truncates the request path. A log line is an
allocation too, and a log file is a disk.

## Harness patterns

These exist in the test files. Use them; do not reinvent them.

**Inject the clock into anything that measures time; never sleep.** The
rate limiters take `now func() time.Time`. Tests advance a `testClock` by
exactly one refill period and assert exactly one token appears. Request
freshness and nonce expiry stay on the real clock deliberately, because those
are agreements with a client; only the limiters read the injected one.

**A test that asserts "not yet" takes its date from the clock, never a
literal.** A window that opens in the future, asserted closed through a
command that reads the real clock, holds only until the date arrives.
`TestTheFirstCreateKeepsDefault` created a channel with `--not-before
2026-10-01` and asserted it was not open, and at midnight on 2026-10-01
it failed on every machine at once, with no change to anything; two more
sites waited ten hours behind it on the same date in UTC, one of them the
container suite's family C. They now take a day a year ahead of today
(`aYearAhead`, `cfpWindow`). Where the code under test takes an injected
clock, a fixed date against a fixed `now` is the better test and stays;
the rule is for the real clock, which is the one a literal cannot keep up
with. And a date the code prints in one zone is compared in that zone:
`auu-ca show` prints an intermediate's expiry as x509 parsed it, in UTC,
and its test took the month from the local clock, so for the first ten
hours of every month here the two were a month apart and the test
failed, found the same night. Before a request, grep the tests for the
year after this one and the one after that, and run the suite with
`-count=1`: the cache is keyed on the source and not on the date, and it
reported that test passing through the hours it failed.

**Inject the sleep into anything that waits.** `client.Client` has an
unexported `sleep` field; the retry tests replace it, record the durations
asked for, and assert `Retry-After` was honoured, without waiting.

**Prove "no database read" by closing the store.** Exhaust the address bucket,
`h.store.Close()`, then send the request. Any read surfaces as a 500, so a 429
proves nothing was read. No counting wrapper, no mock.

**Hold a handler inside the relay with a body that stalls.** `blockingBody`
signals on first `Read` and blocks until released. The in-flight cap is tested
by holding one slot this way and asserting the next request gets 503 with
`Retry-After: 1`, that health still answers, and that releasing the body frees
the slot. No test-only hook in the server.

**Capture logs with a goroutine-safe buffer.** Requests are served on many
goroutines. `syncBuffer` wraps `bytes.Buffer` in a mutex; `newHarness` points
the relay's `slog` at it. Log assertions read `h.logs.String()`.

**Register directly into the store when the test is measuring the budget that
registering would spend.** `h.register` goes over HTTP and costs one
unauthenticated token and one registration token per call; `h.enroll` writes
the mailbox row directly. Using the wrong one produced three failing tests
whose limits had been silently consumed by their own setup.

**Each `newHarness` is a fresh relay with fresh limiters.** Subtests that
need independent budgets get their own harness. Subtests that share a harness
share its buckets.

**Give the harness the response header.** `h.send` returns status, body and
header; `h.retryAfter(header)` insists the value is an integer number of
seconds and never zero. `h.do` predates it and is fine for tests that only need
a status.

## Hostile input

**Build what the real code would refuse to build.** `token.Issue` validates
every rule before signing, so a token with a control character in its note, a
wrong use, or an out-of-order window cannot come from it. `forgeToken` and
`resign` in `internal/relay/admin_test.go` rewrite a payload as a map and sign
it again with a real key, so the relay's own validation is what is tested. The
same idea gives the "signature does not verify" case: keep the payload, replace
the signature with `A` repeated to the same length.

**Pin wire constants from outside the package that defines them.** `resign`
writes the token signing domain `ccx-token-v1` as a literal rather than
importing it. It is a wire constant; if someone changes it in the token package
without meaning to change the format, this test is what fails.

**Cross-verify signatures across domains.** One identity key signs requests,
messages and tokens. `TestRequestSignatureIsNotATokenSignature` signs the
token payload without the domain string and asserts it does not verify as a
token, then takes a real token signature and asserts it does not verify as a
request. Add a signing purpose, add this test for it.

**Forge the identity, not just the payload.** The bad-signature auth test takes
a header signed by one key and rewrites the fingerprint field to name the
victim, so it is a well-formed header claiming someone else. The test then
asserts the victim's own request still succeeds after the attacker has
exhausted the address bucket.

## What the network names

The second adversarial trace (reviews/trace/report-v0.9.0.md, at v0.9.0)
found nothing wrong with any cryptographic or authentication check and
nine faults in what happened after one passed: a thread id joined onto a
path, a turn count keyed on a string the sender chose, a name that two
filesystems spell as one file, a relay's sentence printed as it came.
Every rule here is a test that would have caught one of them.

**Nothing the network names is a path until its rule has run, and one
test walks them all.** A fingerprint in a URL, an upload id, a token id,
an attachment name, a channel name, a relay host, a message id and a
thread id each become part of a path somewhere, and each has a rule at a
named point (security.md lists them in one paragraph, in the test's
order). The test that keeps
this true is a single table: every component, fed `..`, `../x`, `a/b`,
`.`, the empty string and a NUL, asserting the refusal at the point the
table names. When a new place turns something from the network into a
path, its row goes into that table first, before the code. A rule that
is not in the table is a rule somebody will forget.

**A query's text is a constant, and the test parses the tree to say so.**
Beside the file-open ledger, `internal/sqlshape` (test only) finds every
call to `Query`, `QueryRow`, `Exec`, `Prepare` and their `Context` forms
on a `*sql.DB`, `*sql.Tx` or `*sql.Conn`, and requires the query argument
to be a constant expression: a literal, a named constant, a `+` of those,
a local variable assigned only from those and `+=` of them, or a
parameter for which every call of the function in its package passes
one (`certRows` takes its query from two callers that build it by `+=`).
A `fmt.Sprintf`, a `strings.Join`, a function call, a map lookup or a
parameter with a caller that passes anything else fails the test with
the site and the expression; one site is the allowlist, by key, with
its reason: the PRAGMA write, whose operand is the schema version the
store owns. An allowlisted site that is gone is a problem of its own,
which is how the migration's two rows left with the migrations. Two self-tests
plant a `Sprintf` query and a parameter with a non-constant caller and
assert the sentences. A SQL call is told from `url.Values.Query` by its
receiver, an identifier named `db`, `tx` or `conn`, since a type-checker
over the tree would need a loader the dependency rule does not allow; a
prepared statement's `Exec` takes values alone. Values are proven to
travel as parameters by the tests that already send `'; DROP` as a name
and `%` as a short id and assert the row and the refusal.

**Every file operation's path has a row in the ledger, and the test
walks the tree to find the ones that do not.** `internal/fileopens` holds
`ledger.txt`, one line per call site of an `os`, `filepath.Walk`,
`exec`, `sql.Open`, `net.Listen` or `net.Dial` call that takes a path,
keyed by module-relative file, enclosing function (receiver-qualified),
callee and the argument's source text, with its provenance: `local`,
`operator` (with a note after a colon where the store runs the rule
again at the call), `derived: <what>`, or `network: <component>, <rule>
at <point>`, the rule being a function in the tree or, for a component
whose rule is its type (a number the JSON decoder holds to a number),
the standard-library function that writes it, `strconv.FormatInt` or
`filepath.Base`. A helper's row names the least trusted of its callers'
paths. The test parses every non-test file under `internal/` and `cmd/`
with `go/parser`, finds those calls, and fails on a site with no row, a
row with no site, a key listed twice, rows out of order, and a network
row whose rule is none of those; a parse that finds under two hundred
sites fails too, so a broken walk cannot pass by finding nothing. Line numbers are not in the
key, so a row survives an edit above it; a change to the argument
expression is a new site and needs a new row, which is the point. When
this test fails on your change, write the row: the provenance is the
thing you had to know to write the call, and the row is where the next
reader finds it. A `network` row's rule and point should read the same as
the matching row in the paths table.

**A name has one rule, and both ends run it, on every path.** A thread id
is held to a message id's shape, though a new thread is given an id of its
own and not its first message's; a channel name has no slash. Each is one
predicate in one package, called at send and at open, and called on the
stream path as well as the envelope path. The stream manifest once copied
its body into the message unchecked, so a rule that held for a small
message was a door for a large one. The test for a new rule sends the bad
value both ways and by both paths, and the value the sender's own command
refuses is crafted past it with the wire constants as literals, the way
`damaged_test` forges an envelope. An attachment name is the one rule of
another shape: the receiver never refuses a name for what it would do as a
path, since it is no good relying on the sender to get it right; it holds
the name to what any text is held to and writes the file under
`message.SafeName` of it, made unique at the write, and the sender is held
to `SafeName`'s fixed point (`ValidAttachmentName`) at `envelope.Seal` and
`stream.BuildManifest`, so the two ends agree by construction: a name the
sender may ship is one the receiver writes unchanged.
`TestLimitSafeNameIsAFixedPoint` pins every step and the fixed point; the
receiver's tests feed the names past the sender's rule, as a stranger's
client would.

**A string from the network is never sliced before its rule has run.**
`s[:16]` on a fifteen-byte string is a panic, and a fingerprint, a serial
or a token id that a relay lists back is a string the relay chose. The
rule for each id-shaped field in a relay answer runs in the client
package, in one place per answer type, and a field that fails makes the
whole answer a malformed-answer error naming the field and the relay; the
command that prints short ids slices what the client already checked.
The test is a relay that answers one two-byte field for each answer type,
asserting the sentence and the exit code; a panic fails the test by
itself. The same rule holds for a value from a peer: the thread id was
sliced to twelve characters in `auu reply` before it had any rule at all.

**Nothing on the wire is from before, and every required field's absence
has a test that leaves the field out.** A field an end always sends is
required by the other end and refused by name when absent (the rule in
DEVELOPMENT.md); the test for each such field feeds the answer with the
field absent from the JSON — not zero, not the empty string, since those
are what a Go decoder writes for absence and a test that sets them proves
only the decoder — and asserts the malformed-answer sentence naming the
field, the shape it should have and the relay, with nothing of the
answer used, having first fed the answer whole and seen it taken, so the
refusal is the absence and nothing else. A row's fields are left out of
the row; a listing asked for as stubs is fed a row with an envelope. The
client's `TestAnAnswerWithoutARequiredFieldIsRefusedByName` walks the
listing's `allow`, `kind` and `channel`, the stubs envelope, the status
words and the lookup's `created`; `TestARelayWithoutMaxBytesIsRefusedByName`
in `internal/auu` is the health answer through a whole command, and
`TestAListingWithoutAChannelIsRefusedByName` a fetch, with the mail left
on the relay unacknowledged. A count whose zero the relay sends
(`queued`) has no absence test, since absence and zero decode to one
number and the same code runs; its test says so. Formats have the same
rule at the parser: a `ccxt1` token and a `ccx1` export line are refused
by name with the one thing their holder can do, and a test feeds each
well formed. There is no fake old relay in the tree to test against, and
a test that needs a relay that answers otherwise than this one writes a
handler that answers otherwise, for that test.

**A strict decode refuses what follows the value and what reads two ways,
and its test feeds both.** `wire.Decode` is the one strict decode, and every
reader that must refuse an unknown field calls it. It refuses three things
`DisallowUnknownFields` leaves alone. Trailing data is asked of the decoder
as its next token, which must be the end of the input. `json.Decoder.More`
reports whether another value follows and is false before a closing
bracket, so a trailing `}` or `]` passed every "trailing data" check in the
tree — ten of them, the grant documents and the manifest among them — until
the check was `Token() == io.EOF`. A key given twice in one object, or two
keys equal under case folding, is refused, where `encoding/json` keeps the
last. And so is a key that matches a field only by case, which
`encoding/json` takes as that field. Each would let two readers of one
signed document read it two ways. The test for a strict reader feeds the
document whole and sees it taken, then `}`, `]` and a stray letter after it
and sees each refused in the reader's own words, so it proves the new check
and not only the old one. A reader that keeps its own trailing-data
sentence tells `wire.ErrTrailing` apart. Whoever writes a decode of their
own copies the rule rather than the call, and says so.

**A section, an answer type, a request type and a refusal code each come
with the tests that hold the door open.** The door is `sections`, and a
thing that goes through it, or that it is built into, is not done until:

- a new section has a round trip on every path that carries one, with a
  made-up section of its kind riding beside it from the seed (D35:
  `testutil.MadeUpSection`), the kept size at 16 KiB and one byte over, and
  the critical refusal, with the sentence a person reads;
- a new answer type is placed by the relayapi walk, which fails on a body
  type in no set, and has the four rows of
  `TestEveryAnswerTakesNothingNewButSections`: whole and taken, a field it
  does not have refused by name, a section it does not know ignored, and a
  critical one refusing the answer by its name;
- a new request type has the same four rows through its real route and
  signature (`TestEveryRequestTakesNothingNewButSections`), the row that a
  refused request spends no nonce it would not have spent and writes
  nothing, and its decode inside `decodeRequest`, which a walk holds;
- a new refusal code has a row pair, the code present and acted on and the
  same sentence under a code nobody knows and not acted on, and a row
  through a real relay that fails if the relay writes the sentence without
  the code. A handler that answers with the code proves the client and not
  the relay; 6b's no-knocks row did, and a break at the courier's site went
  unseen until the real-relay row was added.

A test pins what the code should say, never what it happens to say. A row
for advice the code gives that is wrong is the bug's test, and it fails.

**A section is known on a path, not everywhere, and its test says which.**
`max-recipients`, read on an answer alone, was known on every path, so a
sealed message could carry a mebibyte of it, kept whole in the record and
re-read at every listing, where a name nobody registered is held to
`wire.MaxKeptBytes`, 16 KiB, and dropped and counted over it. A known
section's test is therefore a table of the feature's section names by the
four paths, `OnMessage`, `OnManifest`, `OnRequest` and `OnAnswer`, every
cell asserted known or not (`TestTheSectionsAreKnownOnTheirPathsAlone`);
and the kept-size row above runs for a known name on a path that does not
read it as for an unknown one, at the kept size and at a mebibyte: the
trace's mebibyte on a sealed note is dropped and counted at the fetch
(`TestASectionNotReadOnTheMessagePathIsHeldToTheKeptCap`). What does not
depend on the path is tested path-blind, in the same test: a
`max-recipients` at the kept size beside a critical `recipient-count` on a
message is delivered, not held for a newer auu, and both are listed among
the ignored sections; and a record an earlier release kept with an
oversized `max-recipients` still loads.

**Nothing on this machine is from before, and every refusal of a file
from before has a test that makes the file in its old form.** A file a
version from before a rule wrote is refused by name, never migrated (the
rule in DEVELOPMENT.md; the relay's database from its first kept version
on is the one exception, under Storage below), and the test for each
refusal writes the file as that version wrote it — the key absent from
the JSON, the old key present, the plain `PRIVATE KEY` block, the
database at the old `user_version` — asserts the sentence whole, with the
file and the fix in it, and asserts that the refusal left the file as it
found it, since a refusal that wrote something is a migration in disguise.
`TestADatabaseFromBeforeTheFloorIsRefusedNotMigrated` walks versions 0 to
10, reads the version back and finds no copy beside the file; `TestAHomeFromBeforeIsRefusedByNameAndNotMoved`
plants each of the four old config keys and each of the three loose
files and snapshots the home; `TestLimitStoredRecordShapes` leaves the
relay out of a record, and `TestLimitPendingRecordShapes` out of an
outbox record; `TestLimitServeLedgerIntegers` counts an attempt with no
`tried`; `TestADirectoryFromBeforeEncryptionIsRefusedByName` writes the
plain block over one key file and over all three; the bundle test in
`cmd/auu-ca` writes a record without `bundle_path`. A key that is
required is proven required by a marshal of the zero value that shows the
key, as the wire's tests do, so absence and the zero cannot be one
thing. The tolerance tests went with the tolerances: the migration tests,
the home's move, the unencrypted authority that still opened, the reply
that guessed the default relay.

**What a filesystem folds is refused at the sender and settled at the
write, and the test skips only where it cannot fold.** Two attachment
names equal under case folding are refused by the sender's rule, so a
Linux sender is told before anything leaves; a receiver takes the pair
and lets the disk say: the spool keeps a stream's attachments by their
index in the manifest, so nothing from the network is joined there, and
the write under `--out` is an exclusive create that on `ErrExist` tries
`x-2.txt`, `x-3.txt`, so whatever a filesystem folds that no rule could
foresee (Unicode normalisation on APFS) is folded by the filesystem's own
answer and nothing is overwritten. The sender's test runs everywhere; the
delivery and extraction tests build a manifest past the sender's rule and
ask the disk whether it folds (`probe` against `Probe`), asserting the
suffix where it does and two files where it does not, so that a pass on
Linux says only what it can. The loop that tries the suffixes has a
ceiling, `maxNameTries`, a thousand, after which the directory is
refused by name with the count rather than tried for ever; it is a bound
the program chose over a loop, which the limit ledger has no kind for,
so its test stands without a row: `TestLimitTheNumberedSuffixHasACeiling`
plants 999 names and sees `name-1000` written, then the thousandth and
sees the refusal, the thousand files as planted and no temporary, on
both write paths.

**A count against a quota is one arithmetic in one helper, and the test
drives every caller through it.** `Put` and `OpenUpload` each compared
against the same quota with their own sums, and only one of them counted
the other's reservations. The helper answers the question once, by
subtraction (`size > quota - queued - reserved`, never a sum that can
wrap), and the test for a quota opens a reservation through one caller
and asserts the refusal through the other, in both directions.

**A limit keyed on a string the sender chose is not a limit.** `max_turns`
counted answers by the thread id in the follow-up, so a follow-up under a
fresh id was on turn one. A limit is keyed on something the ledger already
holds: the thread of the message being answered, found by the reply's
`in_reply_to`. The test for any per-thread limit sends the follow-up with
a renamed thread and asserts it is not answered and the count does not
move.

**Housekeeping never waits on a sender.** A purge that runs inside an
unrelated caller's request took the lock an attempt holds across its body
read, so one dribbling upload stalled every hundredth request. Housekeeping
uses `TryLock`, skips what is held and returns to it next time. The test
holds an upload's lock from a goroutine that is still "reading" and asserts
the purge returns within a bound while the lock is held, then that the
skipped upload is gone after the lock is released and the purge runs again.
A partial an attempt leaves lives sixty seconds from the moment the
attempt stopped and no longer: the window is a constant on the relay's
clock, not a setting, read once the copy has ended and never when the
request began — the first cut stamped it before the copy, so a transfer
that ran longer than the window before its link dropped was kept already
expired, and at the shipped stall deadline every stall-cut partial was.
The test resumes at 59, at 60 (the edge is inclusive) and at 61 seconds,
where the answer is 410 and the partial is gone, and parks an attempt past
the threshold with its bytes on the disk while the clock moves ninety
seconds before the sender closes, asserting the window counts from the
close; a sender whose bytes stop coming is cut by the hunk deadline
inside the same window, which the test bounds in wall time with the deadline set
short.

**A number from the network is bounded before it is multiplied or
allocated from, and the test is the value one over the bound.** The sweep
after the second trace found every parse in the tree already doing this,
and the shapes are worth copying: the freshness window compares against
both edges and never subtracts (relayapi.go, `FreshAt`); `Retry-After`
is clamped to a named maximum before it is multiplied by `time.Second`
(client.go, `retryAfter`); a list `limit` is capped and `after` refused
below zero before either reaches SQL; a stream header's chunk length is
held to `[MinChunk0, MaxChunk0]` before the buffer is made; a manifest's
attachment sizes are checked against what is left of `MaxPayloadBytes`
before they are added; an agent frame's length is checked against
`MaxFrame` before `make`; the key file's Argon2 costs are bounded so the
`uint32` and `uint8` casts cannot narrow. The two that multiplied first
(the agent's unlock TTL, auu-admin's printed seconds) are in the same
plan as this rule. For any new number from the wire, the socket or a
file, the test drives the bound, one over it and the type's MaxInt64,
and asserts the refusal or the clamp, never the wrapped value.

**A message's own words are held to a rule at Validate, again at Load,
and escaped again where they are shown.** A subject is one line: no
control, format, private-use or separator rune, refused at both ends on
both paths. Text keeps newline and tab and nothing else from those
classes. An attachment name is held at Validate to one line, UTF-8, no
NUL and a size, and the rest of that set is the sender's rule and
`SafeName`'s `_` at the write, never a refusal of the message. A record
read back from the spool is held to the same rule at `Load`, and one that
fails it — written by hand, or by a version from before the rule — is
refused by name and said once by the listing, not shown
(`TestLimitStoredRecordShapes` plants each rune;
`TestWhatASenderWroteReachesTheTerminalEscaped` shows the listing's
warning and that nothing of the record is printed). And every print of a
subject, text, name or sender goes through an escaper all the same, as
the last line under the rule; `--json` is encoding/json's.
The test for a rule is a table at `Body.Validate` and `Manifest.Validate`
with ESC, `\r`, a bidi override, a private-use rune, U+2028, a newline, a
tab and invalid UTF-8, saying for each field whether it is refused or
kept; the test for the escaper saves a record by hand with an ESC in
every field and asserts no 0x1b reaches stdout from `inbox`, `quarantine`
or `read`. A quarantine listing prints what a stranger wrote, so it is
never left out of that test.

**Nothing is ordered by a clock the sender set.** A thread's latest
message, its opener and the completion list were ordered by the sender's
timestamp first, so a peer stamping year 9999 was "latest" for as long as
the message was kept. Order by arrival here, then the relay's id; use the
sender's time to break a tie and to display. A timestamp ahead of the
receiver's clock by more than the freshness skew is malformed at open. The
test sends the earlier-arriving message with the later stamp and asserts
the later-arriving one is picked, and seals an inner a day ahead and
asserts malformed.

### The ways a string goes wrong, and the value that shows each

A string from the network is bytes with a claim attached: that it is text,
that it is one line, that it is a name, that it is hex. Every rule in this
guide about names and paths is a rule about one such claim. This is the
list of claims, each with the way it fails, this tree's example, and the
value the test feeds. Go helps less than it looks: a `string` holds any
bytes, `len` counts them, `s[i]` is a byte, `range` yields runes and
silently gives U+FFFD for a bad one, and `==` compares bytes, all of which
is right for some claims and wrong for others.

**It is UTF-8.** A string that is not is still a string. `range` turns
each bad byte into U+FFFD, `strconv.Quote` writes it as `\x..`, a terminal
does what it likes. But note where the check runs: `encoding/json`
replaces every invalid byte with U+FFFD as it decodes, so a
`utf8.ValidString` after `json.Unmarshal` is a rule on nothing for a
JSON-carried field. It still earns its place, for a record built in code
or read from a file the program did not write; the test for the wire is
at the byte level, before the decoder (a body with a lone `0xff`), and what
it proves is that the decoder replaced it and the rules downstream saw
U+FFFD, which is printable and harmless. The escapers here write a bad
byte as `\xff`, and the test for them feeds one directly.

**It is one line, or it is a name.** Category Cc is the control characters,
including newline, tab and ESC; Cf the format characters, including the
bidi overrides that reverse a line and the zero-width joiners that hide
in it; Co private use; Zl and Zp the line and paragraph separators, which
are not `\n` and pass a check for it. `channels.ForbiddenRune` is the one
set, and a subject, a channel name, a description, an attachment name and
a certificate label are held to it; a message's text keeps `\n` and `\t`
and nothing else from it, and the two places this program makes a text
from a file — `auu send` from a body file or standard input, `serve` from
a handler's output — fold CRLF to `\n` first, since Windows writes it and
a refusal naming U+000D at every send would be the wrong sentence for an
honest file; a lone `\r` is still refused. Test values: ESC, `\r`, U+202E, U+200D, U+E000,
U+2028, U+0085 (a control that is also a line break in some places), and a
newline, saying for each field whether it is refused or kept.

**Bytes are not characters, and neither is width.** `len(s)` is bytes;
`s[:12]` can cut a rune in half and print `\xe2`; `%-32s` pads by runes
but a terminal advances by cells, and an East Asian wide character takes
two, a combining mark none. `truncate` cuts on a rune boundary now
(auu-admin's cut bytes until the second trace). Lengths on the wire are
byte caps, because bytes are what is allocated and signed, and the test
value is a name of exactly the cap in bytes whose last rune straddles it.
Column alignment is cosmetic and is not tested; a bidi override in a
column is not cosmetic and is refused above.

**Two names are two names.** Identity names, channel names and attachment
names are compared byte for byte, so `Bugs` and `bugs` are two channels,
and that is the rule the documents state. The one place folding matters is
the disk, where a directory is named for a value: macOS by default and Windows spell `Report.txt` and
`report.txt` as one file, so attachment names are also refused when equal
under `strings.EqualFold`, and a collision the disk still finds (Unicode
normalisation, which the standard library cannot check) is refused at the
open, and `serve check` refuses two channel names equal under `EqualFold`
since each is a directory under `serve/channels/`. Compare with
`EqualFold`, never `ToLower` then `==`: `ToLower` is not
a fold (U+0130 lowers to two runes; the Kelvin sign K folds to k but
lowers to itself). Test values: `Makefile`/`makefile`, `K`/`\u212a`, and
on a folding filesystem the NFC and NFD spellings of `é`, the test
skipping where `probe` says the disk keeps them apart.

**It is a base name.** No `/`, and on Windows no `\`, no `.` or `..`, no
NUL, and then the things Windows adds: a trailing dot or space is
stripped by the filesystem, so `report.txt.` is `report.txt` and
collides; a device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`..`COM9` and
`LPT0`..`LPT9` with their superscript forms `COM` with U+00B9, U+00B2 or U+00B3, the
union of what Microsoft's pages have listed) with any extension or none
opens the device rather than a file, so an attachment named `nul.txt`
writes nowhere and one named `con.txt` writes to the console. Test values: each of those, `a/b`,
`a\\b`, `..`, `.`, `.hidden`, a trailing space, a trailing dot,
`%2F` (which must stay literal in a name and become a segment only in a
URL), and the empty string. For an attachment name each of these is what
the sender may not ship and what `SafeName` turns into a base name at the
write (`x`, `_CON`, `_hidden`, `attachment`), asserted by the expected
output per row; `filepath.Base` at the open is belt and braces, never the
rule.

**It has a shape.** Hex is 0-9a-f, lowercase, of one length; a message id
is 32 of them, a fingerprint 64, a short id 16; base64 has an alphabet and
a length modulo 4. A rule on shape is also what makes a string safe in
other syntaxes: a short id goes into `LIKE ?` with `%` appended
(store.go:784), and `%` and `_` are wildcards there, so it is the hex rule
before it that keeps a short id from matching every mailbox. A name
derived from a value the rule may refuse is made valid first and only
then suffixed, and a loop that tries suffixes has a ceiling:
`defaultRelayName` tried an IPv6 host as it was and every suffix failed
the same way, so `auu relay add https://[::1]:8443` spun for ever until
the file-path review. Test values
for every shape: the empty string, one under and one over the length,
uppercase, a wildcard character, a space at either end, and `+1`, ` 1`,
`0x1` and `1e3` for a numeric string (`strconv.ParseInt` with base 10
refuses all four; `Atoi` accepts `+1`).

**It is a number written down.** `strconv.ParseInt(s, 10, 64)` refuses
signs it did not expect, whitespace, a base prefix, an exponent and an
overflow, and each refusal is an error the caller must look at. A JSON
number lands in an `int64` only if it is an integer that fits; `1.0` and
`1e3` are refused, `-0` is 0. Time as a string is RFC 3339 through
`time.Time`'s own decoder, which refuses years outside 0000–9999. Test
values as in the shape rule, and the integer rules above for what the
number is then used for.

**It is a secret.** A token, a capability, a passphrase: compared with
`crypto/subtle.ConstantTimeCompare`, never `==` in a loop over candidates,
because `==` stops at the first differing byte. A map lookup keyed by the
secret is acceptable: Go's string hash is seeded per process and the
comparison runs only on a hash match (the proxy looks a capability up in
`p.live` that way; its loop over `p.revoked` compares dead tokens, which
leak nothing). Test: none for timing; the rule is read.

**It is echoed.** An error that repeats its input repeats whatever the
peer wrote. Where a sentence must name a value, it is `%q` or through an
escaper, never `%s`; where the value is the thing that could not be
trusted, the sentence names the field and not the value (the client's
malformed-answer error). The relay's own sentences are escaped where the
client builds the error, so the relay cannot drive a terminal through a
refusal. Test values: ESC and a newline in the input, asserting neither
reaches standard error as itself.

**It goes into another syntax.** A string is safe in exactly the syntax
it was checked for. Into SQL only as a parameter, never by `Sprintf`; into
a shell never (arguments are a slice to `exec.Command`, and a handler's
subject and sender name travel as environment variables and a file, not
as a command line); into a URL path through `url.PathEscape`, so a slash
in a value is `%2F` and one segment, or, for an id, its shape rule
before the join (`token revoke` joined an unchecked id until the string
review, and `x?all=true` was a path and a query); into a log line truncated and quoted;
into JSON through `encoding/json`, which escapes what JSON needs and no
more (a terminal escape survives JSON, so `--json` output is for programs,
and that is documented); into a file name only after the base-name rule;
onto a terminal only through `Printable`, `PrintableText` or
`PrintableLines`. Test: for each new sink, the value that is a
metacharacter in that syntax and nowhere else.

**Empty means something.** An empty channel is the default channel; an
empty subject is allowed; an empty name is refused; an empty fingerprint
in a listing is "not present" in one answer type and malformed in
another. Every rule says what empty means, and the test feeds it. The
same for whitespace: a name of spaces, a leading or trailing space, and
`TrimSpace` before the rule where the rule allows it (a passphrase is
never trimmed).

**It is a prefix.** A short id matches a fingerprint by prefix, and a
thread by the first characters of its id. Two matches are ambiguous and
say so with both candidates; zero say so; a prefix shorter than the rule
allows is refused before the lookup, since a one-character prefix would
match a sixteenth of everything. Test values: a prefix with two matches,
one, none, the empty string, and the full id.

For a new string from outside, the recipe: write down every claim the
code makes about it (text, one line, a name, hex, a number, a secret, a
prefix), the syntax of every sink it reaches (terminal, file name, SQL,
URL, log, JSON, environment), and for each claim and each sink the one
value that breaks it. A rule at the boundary, one escaper per sink, and a
test row per value.

**A trace's test is kept under a name that says what it proves, and its
assertion is never weakened to make it pass.** The tests under
`reviews/trace/` fail on the code they were written against; when the fix
lands, each becomes the regression for its commit, renamed for what it now
proves (the refusal, the sentence, the absence of the file), with the
assertion changed only from "this happens" to "this is refused". A test
made to pass by asserting less proves the fix was not made.

## Limit tests

A limit test takes a value from outside to the edge of what the code allows
and one step past it, and shows what happens there: an error with a
sentence, never a panic, never a silent clamp, never a number that has
rolled over. Its name starts with `TestLimit`, so that `go test ./... -run
'^TestLimit'` runs the category on its own, and every one is listed in
`internal/limits/ledger.txt` beside the site it shows. The test in
`internal/limits` walks the tree for the sites and holds the ledger to them:
a site with no row, a row with no site, and a row naming a test that does
not exist each fail it.

There are five kinds.

**An integer with a range.** For every integer from outside that the code
holds to a range (`lo <= n <= hi`, `n <= max`, `n > 0`), the test feeds
`lo-1`, `lo`, `hi`, `hi+1`, and the minimum and maximum of the integer's
type: `math.MinInt64` and `math.MaxInt64` for an `int64`, `0` and
`math.MaxUint32` for a `uint32`, `math.MinInt` and `math.MaxInt` for an
`int`, written as the type's constants and not as literals. When the value
arrives as text, the text forms too: the string one past the type's
maximum, a leading `+`, `-0`, a leading space, a digit outside ASCII. The
assertion is the specific error for each value outside the range and the
specific acceptance of `lo` and `hi`.

**An integer with no upper bound.** A count, a size, a sequence number, a
duration, an offset: any integer from outside that the code takes without
a ceiling. The test feeds `-1`, the type's minimum, `0` and the type's
maximum, and asserts that a negative is refused with an error before the
value reaches arithmetic, an index, a `make`, a `Sleep` or a database. A
function that takes such a value and cannot refuse it today starts
returning an error, and its callers change to carry it; that is the point
of the test, not a departure to note. `0` is fed on its own because empty
and absent are different things (see "Empty means something").

**A string under a range.** Every slice of a string or a byte slice,
whatever its bound: the second trace's panic was a constant `[:16]` on a
two-byte fingerprint from a listing, and the rule that made it safe was
upstream and unnamed until a row named it. Every offset taken from a
length field, every `Index` followed by a cut. For a cut with no rule
upstream, the test feeds the empty string, a string one byte shorter
than the range needs, a bound one past each end, an end before its start,
a bound that came from a negative number, and a multi-byte rune
straddling the cut, and asserts the error at each. For a cut whose
operand a rule fixed the length of, the test is the rule's, one per rule
and shared by every cut it guards: it feeds the operand one byte short at
the rule's point and asserts the rule refuses it before any slice runs.
A panic is a failing test, and so is a slice that succeeds on a string
that was too short. A slice whose operand has no rule upstream is the
finding, and the fix is the rule, not a length check at the slice.

**A path from outside.** Every row of the file-open ledger whose
provenance is not `local` (network, operator, derived from either, and any
value read from a configuration file) names, after `shown by`, the limit
test that drives the traversal set through the rule at that point: `..`,
`../x`, `x/../../y`, `a/b`, an absolute path, a backslash form, a drive
letter, a drive-relative name, a Windows device name with and without an
extension, a NUL byte, the empty string, `.`, and a name longer than the
filesystem allows. The assertion is one of two: the operation refuses
with its sentence, or the path it resolves stays under the directory it
was meant for (`filepath.Rel` from the base has no `..` element); and in
either case a witness file outside the directory is still there and
nothing new is beside it. An operator's path comes in three forms and the
row says which. A whole path used as given, a flag or a file named on
the command line, is `operator's absolute path` and names no test, since
nothing is joined onto it. A value from a configuration file is resolved
against that file's directory, never against the working directory the
program was started in — the third review found the relay's `db`,
`messages_dir` and `admin.authorized_file` and serve's channel `dir`,
`key_file` and `control` all relative to wherever the process happened to
start, so that a unit file and a shell gave the same settings two
meanings — and its row says the base and names the test that shows a
relative value land beside the file and an absolute one kept
(`TestLimitConfigPathsResolveAgainstTheirFile`). A name the operator
chose that is joined under a directory, a relay name under `relays/`, is
held to the same rule as one from the network, and its row names the rule,
the point and the test. A directory entry is a path too: a reader that
lists a directory it owns and joins each entry back onto it holds the
entry to a rule of its own — a message id, a relay name, a file and not a
directory — and its test plants strays that break the rule (a file where
a directory is expected, a directory named `CON` or `..x` or by a name
one short of an id, a directory with a file in it where only files
belong) and shows the reader skip or list them by name, read what the
program wrote, remove nothing that is not its own, and never fail the
start on one of them. The relay's sweep once failed the whole start on a
directory somebody had made inside a mailbox, because `os.Remove` of it
was an error; the reader's rule is the fix, not a broader remove.

**A cap on what is read.** Every reader the program bounds —
`http.MaxBytesReader` on a request body, `io.LimitReader` on an answer,
`MaxHeaderBytes` on a server and `MaxResponseHeaderBytes` on a transport
— has a row in the ledger saying the bound, and a test that feeds the
reader a body or a header block at the bound and one byte over, and
asserts the refusal by name at one over: the 413 with the cap in its
sentence, the 431, the answer refused as malformed naming the hold. A
reader that is cut at its bound and fails later as something else — an
answer read short and refused as JSON, an error body read short and
reported as an empty sentence — is the finding, and the fix is the
refusal by name where the bound is: the client's stream-route answers
and its trust anchor fetch were three such cuts, found the day the walk
first looked for caps. A bound that is the program's own arithmetic on
values it already holds, with no edge from outside to feed — the sealed
copy's size less the offset, the row's size less the offset that
Content-Length was held equal to — says so in its row as `local:` and
needs no test of its own, though it may name the test of what made the
values equal. A hold sized by a relay's word is held to a client constant
too, and its test feeds the largest word the relay may say. The listing
hold was twice the `max_bytes` a health answer gives, which the client
admits up to `MaxBytesCeiling`; the cap row for the reader every answer
goes through, `(*Client).attempt` at `<= hold + 1`, and its test at an
ordinary relay's figure proved the reader and not what sized it, and a
relay saying a gigabyte had a hold of two. `TestLimitListingHold` feeds
`holdFor` figures up to `MaxBytesCeiling` and shows the hold at
`MaxListingHold` from 64 MiB up, then, through `List` against a relay
saying the ceiling, takes a page of exactly `MaxListingHold` and refuses
one a byte longer naming it; the trace's
`TestTheListingHoldIsBoundedWhateverTheRelaySays` holds what refusing that
relay's page allocates under three times the hold.

A name list is one guard, and a name list is never complete. The other is
the handle: a device is a device whatever it is called, and so is a named
pipe, a socket or a directory, and the open file knows. So every file the
program reads or creates by a name from the network or from a directory
entry it read back is opened through `internal/regular`, which opens,
asks the handle for its mode, and refuses anything that is not a regular
file before a byte moves; a create is exclusive (`O_EXCL`, and
`O_NOFOLLOW` where the platform has it), so the program never opens
something that already stood under that name, and there is no rename onto
a name from outside, since a rename's destination has no handle to ask.
The file-open ledger says which rows are held to this, and its test fails
a network row or a directory-entry row that opens by the plain `os` call.
The proof runs on both kinds of machine: on Windows, `CON`, `NUL`,
`nul.txt` and `com1.txt` through the helper, asserting that each is
refused by the handle with the sentence naming the device, or refused by
the platform, or — since Windows versions differ in which of them is a
device under a directory — made as a regular file, and never a device
handed back as a regular file, and `CON` through extraction under its
safe name; on Unix, a FIFO, a symlink to a device and a directory planted
under a valid name, asserting the same, with a witness file untouched. An operator's own input file is not held
to this: a passphrase file from process substitution is a pipe on
purpose.

A list in the tree is never the source. It is either derived from its
source when the program is built (the Unicode tables, the library's own
constants, the wire's constants shared by both ends) or held to its source
by a test that runs on the platform that owns it, and on that platform the
source is asked at run time wherever it can be: on Windows the device rule
asks the OS through `filepath.Abs`, and the hand list is for the other
platforms, which the Windows job holds to what the OS said. Where the
source's versions differ — Windows Server 2025 resolves `NUL` alone
under a directory, older Windows the whole DOS set — the list is the
union, held one way: every name the OS on the runner calls a device must
be in it, and it may be wider; and the OS check at the open, the handle
asked its mode, is the safety net for whatever the list does not hold.

**The ledger.** `internal/limits/ledger.txt` holds one row per site the
test finds:

    <file> <enclosing function> <kind> <site as written> = <range or open> shown by <TestLimit...>

The sites are: a field of integer or duration type, or of a map or
slice whose values are integers (a byte slice excepted), in a struct
with a `json` tag, exported or not, wherever the struct is declared — at
package level, inside a function (`cmdShow.relayOut`), or as a literal's
anonymous type (`cmdShow.struct`); a call to `strconv.Atoi`,
`strconv.Parse*` or `time.ParseDuration`; a `binary.*.Uint*` read (a
`Put*` is a write, and is not a site); an integer or duration flag,
which in this tree is always a `*flag.FlagSet` method; a slice
expression on a string or a byte slice, whatever its bound, and on any
other slice with a bound that is not a constant (an array's bounds are
checked at compile time); and a cap, a reader bounded by
`http.MaxBytesReader` or `io.LimitReader`, written as the callee with
the reader and the bound, or `MaxHeaderBytes` set on an `http.Server`
or `MaxResponseHeaderBytes` on an `http.Transport`, written as the field
and its value. The range is `[lo, hi]`, a floor or a ceiling
(`>= 0`, `> 0`, `<= n`), a set (`one of 44, 65, 87`), or `open`; a
duration's bound carries its unit (`>= 5s`), and `0 or` in front says
zero is a sentinel the range does not otherwise hold, the default or
unlimited. A duration read from text is fed the integer forms and the
duration forms that bite: no unit, a negative, an overflow
(`9223372037s`), `inf`, empty, a unit alone. A struct the program only
writes and never decodes says `= output` and names no test, and the walk
proves the claim: it finds every argument of `json.Unmarshal` and
`Decoder.Decode` in the tree, directly or through a helper whose `any`
parameter reaches one, and every type reachable from one through fields,
slices, maps and pointers, and a field of any such type cannot be
`output`. An unexported field that is filled by parsing a string carries
the range the parse enforces and names the parse's test.
`internal/testutil` is imported by tests only and is skipped, and the
walk checks that nothing outside a test imports it. A slice's row says
one of two things in place of a range. `local: <Rule> at <point> shown
by <TestLimit...>` names the rule that fixed the operand's length and
the point it ran (`local: ValidFingerprint at checkMailbox`); the walk
holds the rule to the tree, the function must exist, and the row names
the rule's test, one per rule, shared. `local: <why>` of any other form
is the operand's own arithmetic (`local: len(s)-1 of s`, a length the
code checked, an index a loop or `Index` gave, a rune boundary), and
names no function and no test. A cap's row says the bound as the site
reads under it: `<= n` where the bound is a constant, and the walk holds
`n` to the constant's value in the tree (a reader bounded one over its
route's hold, so an answer over the hold is known to be over it, says
the hold plus one); `<= hold + 1`, the name the code gives it with its
arithmetic, where it is not; `one of a, b` where the bound is a
parameter and the callers give it more than one; or `local: <why>`
where the bound is the program's own arithmetic, which may name a test
and need not.
The test holds the file to the tree the way the file-open ledger does: no
site without a row, no row without a site, no test named that does not
exist, and a floor on the count, so that a walk that finds nothing is
itself the finding. A row's test may be shared: one `TestLimit` over a
struct's `Validate` can show every integer field of that struct, and one
over a rule can show every path row that names the rule.

**A time from outside has a row in the ledger, as an integer does.** The
third trace found no time kind in the ledger, about seventy `time.Time`
fields in wire and record structs, and their bounds written by hand,
each differently: a message, a manifest and a vouch refused a stamp from
the future, and the three owner documents, the allow list, the card and
the channel directory, took one from any year. The ledger now has a
fourth kind, `time`: a field of a json-tagged struct of a type that
holds a time: `time.Time`, a struct embedding one, a type defined over
it, or a pointer, slice, array or map of these, a map by its key too;
and every `time.Parse` and `time.ParseInLocation`. A type defined over
`time.Time` does not decode from a string; it is taken because it holds
a time. Its row says `<= now + 5m`, the skew, with a test that feeds
the edge, a second either side, a day and a year ahead, a year past, and
the earliest and latest instants; `[lo, hi]`; `deadline: <use>`, with
a test that feeds the earliest instant and one past year 9999 and shows
no panic and no overflow; `display`; `output`; or `local: <why>`.
Where the wire cannot carry those extremes, the test shows the encoder
refuses them and feeds the wire's own ends through the reader instead.
The latest instant is
`time.Unix(math.MaxInt64-62135596800, 999999999)`, not
`time.Unix(math.MaxInt64, 0)`, which wraps to before 1970. The ledger's
header gives the grammar of each, and is the place to read it.
`display` is held by the walk: it refuses the row when the field, or a
time derived from it by a `time.Time` method, a dereference or an
index, is an operand of `Before`, `After`, `Equal`, `Sub` or `Compare`,
an argument of `time.Since` or `time.Until`, a side of a comparison (a
pointer, slice or map held against nil excepted), or read in a
comparator written in the call that sorts, `sort.Slice` and the like,
or in a `Less` method, anywhere in the tree. That is not every way a
time can be compared, and the row is read against its field for the
rest; among them a copy into a local, or into a struct with no row, a
comparison through `Unix` or `UnixNano`, a defined type converted back,
a method promoted from an embedded time, a helper of the tree's own
that compares, a whole struct compared, a comparator held in a variable,
and a file the build leaves out. And the decoder walk now follows a
helper across packages by its name, so a field decoded through
`wire.Decode` from another package is reached as one decoded in place,
and `output` on a wire answer means what it says. The floor is 542.

**Two bounds on the same value in two encodings are read against each other.**
`MaxSaid` bounds a relay's refusal sentence at 512 bytes and `MaxReportBytes`
bounded the JSON body carrying it; the second was a kibibyte with a comment
saying "room enough twice over", and that was false, because `encoding/json`
escapes `<`, `>` and `&` to six bytes each and those are characters the sentence
rule permits. A legal sentence of 512 ampersands encodes to 3,125 bytes, so the
relay being told refused it before the shape was read, the relay passing it back
read that as final and ended the chain, and the sender waited out `forward_ttl`
to be told the neighbour was unreachable. The bound is now derived from the one
it depends on with each term named, and — this is the part worth copying — every
number in the comment is asserted against the encoder by a subtest. An
arithmetic in a comment is a claim like any other, and the first version of that
one was wrong in its third term as well.

**A test that pins a constant pins nothing; pin the claim.** Asserting that a
default equals its own literal restates the line above it and would be just as
true of a wrong value written first. What is worth holding is the relationship
the documentation explains — that the reporting rate is a tenth of the posting
rate, with the two durations that follow from it — so that changing either number
for a good reason fails the test and asks whether the ratio was meant to go too.

**When a limit test finds something.** The change it forces is the
smallest that makes the sentence true: a check before the arithmetic, an
error returned where none was, a function that took an `int` refusing a
negative. Not a silent clamp, not a conversion to an unsigned type, not
a comment. Where the documented contract says a value over a cap is
served at the cap, as a listing limit over MaxListLimit is, that is not
a clamp but the contract: the row names the cap and the test shows a
value over it served at it and says so. The test keeps the name that
says what it proves, and the ledger row points at it.

## Storage

**A database has three answers, and each has its test.** Below the floor,
`TestADatabaseFromBeforeTheFloorIsRefusedNotMigrated` opens a fresh store,
writes each `user_version` from 0 to one under `firstKeptVersion` with
the store's own handle, closes it, opens it again, and asserts the
sentence whole — the file, the version found, the version written, the
floor, the message directory beside it, and what the deletion costs —
then reads the version back through a raw handle and looks for a copy
beside the file, to show the refusal wrote nothing. Above this build's,
`TestNewerDatabaseIsRefused`. From the floor up,
`TestADatabaseAtEachKeptVersionIsCarriedForward` builds each kept version
from its `schemahistory` text, the old DDL pasted from git and never
derived, plants rows written by today's store and copied in over the old
file's own columns, and after the open asserts the version, the copy (its
mode, its version, its rows), every row through the store's own readers,
the sweep, the counters, and then the shape: `PRAGMA table_info`,
`index_list` and `index_info` equal, row for row, to a fresh database's,
both ways round. That comparison is what holds the steps to the schema
constant, and it is the rule that went with the first migrations and came
back with the second. A version written in more than one shape — 12, with
three indexes on outbound or five — runs in each. A step that fails, and a
copy that cannot be made, each have a test asserting the sentence and the
database left at the version found.

**Corrupt the counters and reopen.** Set `queued_messages` to nonsense
directly, close, `OpenStore` again, assert `Reconciled()` is non-zero and the
counters agree with a fresh `COUNT` and `SUM`. `assertCountersAgree` does the
comparison for every mailbox and for `relay_stats`.

**When the threat is the host, edit the row, not the wire.** The allow list
was a plain table the relay trusted, and the plan that signed it asked for
one test above the others: `UPDATE allowlists SET doc = …` through the
store's own handle to admit a stranger, then a post from that stranger
through the HTTP path, refused with the sentence a refused sender always
gets. Against the old code the stranger is admitted and the test fails,
which is the point. A test that pushes a forged document over
the wire proves the push's check; only a test that writes the database
proves the enforcement's. The same test then edits one byte of the
signature and replaces the mailbox's bundle, and asserts the owner's own
request fails too, since that is what the model says an attacker buys.

**Refuse the databases you must refuse.** Version zero with tables present,
any version below the first kept one, and any version above the current
one, each with the specified message. All three are tested; keep them
passing when you bump the version, and give the new version its step, its
`schemahistory` text and its row in the carried-forward test.

## Logs and privacy

**Assert what is absent.** The minimal-access-log test posts a message and then
asserts that neither the sender's nor the recipient's fingerprint appears
anywhere in the captured log, and that there is no `fp=` field at all. The
audit test greps the whole log for the token string and for anything starting
`ccxt1.`.

**Assert what is present in both modes.** The audit line must carry
`action=`, `admin=`, `target=` and `outcome=` under both `full` and
`minimal`. Run the same body under each mode with `t.Run`.

**The `limit=` field turns a wall of 429s into a diagnosis.** There is a test
that a refusal produces it. Add a limit, extend that test.

**A log line the server writes after it has answered is a race to read;
wait for it with a deadline.** The key-holding proxy writes its request
line after the response has been copied to the client, because the line
reports the status, the bytes and the time taken, and writes its refusal
line after the refusal; with the flush interval at -1 the client finishes
reading, the test reads the buffer, and the line is not there yet — once in
a thousand idle runs here, twice in three hundred on the reviewer's
machine, and CI's ubuntu job on a push that had not touched the proxy. The
line must come after the answer, so the test waits: `waitForLog` polls the
buffer with a deadline of five seconds and fails with the whole log, and
every assertion on a proxy line — a request, a refusal, a mint, a
revocation written by the socket's goroutine after the client closed — goes
through it, with the negative assertions (no key in the log, not the whole
token) made on the log it returned. Any line a goroutine writes after the
thing the test waited on is the same shape.

**A change the relay reports is not the end of the command that made it;
wait for the process, not the event.** The same shape across processes. A
push PUTs the directory to the relay first and writes the local record
after; a watch in the test's own process reports the change as soon as
the relay has it; and the watch tests started the next step's command for
the same user, in another process, on that report — while the previous
process might not yet have written its local directory, which the next
one reads. On every fast machine the write won; on CI's ubuntu runner,
with the package at 519 seconds, it lost once, and `channel delete` found
"a directory issued T, newer than this machine's", T being the step
before. `onTheHold` now keeps its process's done channel on the user and
the next command for that user — in another process or in this one —
waits on it first. When a test chains steps through separate processes,
the thing to wait for between them is the process's exit, never the
event it caused.

**A line limited to once a minute is tested as one line for a burst and a
second after the clock advances.** The fault log's limiter is keyed by the
thing the line is about — a path for a storage fault, `allowlist:FP` for a
list that no longer verifies — never by the sentence alone, since two
mailboxes broken at once are two lines an operator needs. The allow-list
test refuses two senders inside the minute and counts one line, advances
the harness clock two minutes, refuses again and counts two. Both halves
matter: the first proves the limit, the second that it lifts.

**A worker's clock is injected and its waiting is a function, so a test drives
turns rather than sleeping.** The forwarding worker backs off per neighbour, up
to an hour, and gives up after three days; a test that waited would be a test
nobody runs. The harness stops the workers a relay starts for itself and drives
`drain` and `attempt` from its own goroutine against an advancing fake clock, so
a backoff, a give-up and a purge each happen where the test can see them. Two
faults came out of making that injectable and both are the kind only this shape
finds: taking the return out of the `select` it replaced left a loop whose only
exit was inside the thing it called, so it spun on a cancelled context and every
test that built a relay with a neighbour hung before its first line; and a
neighbour's backoff written only into the set, and not onto the row, came back as
a dial per held row after a restart.

**A chain is tested with real relays and nothing between them faked.** An
undeliverable that unwinds needs three: with two, the sender's own relay is the
one that meets the refusal, so its row ends correctly and nothing has to travel
— which is exactly why the one-hop defect survived a two-relay test and was found
by a three-relay one. Each relay gets its own store, its own courier home naming
the next by its own name for it, and its own couriers file admitting the one
behind. Two things that shape costs: a mutual peering is a knot, since each side
reads its neighbours' addresses at the start and neither address exists until a
listener does, so both listeners open around a handler filled in afterwards; and
each relay's courier must be the identity its neighbour's file admits, which is
why the fixture takes the identity rather than generating one — a chain whose
relays each generate their own signs as keys nobody admitted and every hand-over
is unauthorized.

## Command-line and end-to-end

**Drive the real prompt through a pipe when the prompt is the thing under
test.** `user.answer("n", ...)` replaces `os.Stdin` with a pipe carrying one
line. `TestEnrolDeclinedLeavesNothingBehind` declines and then asserts no
identity and no config were written. `--yes` is for tests where the prompt is
incidental.

**Run the CLI end-to-end tests against the shipped defaults.** `startRelay`
uses `relay.DefaultLimits()`, not an unlimited relay, so the defaults are
proven usable by the CLI on every run. A test that needs different limits
uses `startRelayWith` or `startRelayConfig` and says why.

**Test the settings file you ship, not only the harness's.** Every relay
test set client certificates on, and the template under `docs/systemd/` has
them off; the anchor route was closed in exactly that configuration and no
test noticed until a deployment did. `TestTheShippedTemplateServesItsAnchor`
loads the template itself, replaces only its paths, and makes the first
request a machine makes. When a document tells an operator to install a file,
a test loads that file.

**A unit file is checked by running it under systemd, and a warning from
`systemd-analyze verify` is a failure.** systemd ignores a directive it does
not know with a warning and starts the service anyway, so a misspelled
`LoadCredentialEncrypted=` is a relay that starts with no bundle and a
credentials directory with nothing in it. `scripts/systemd-check.sh` runs
the deployment guide's steps 2 to 7 on the machine it is given — the shipped
unit and settings, `systemd-creds`, the credential, an enrolment, a
rotation, the unit with its credential line removed — and greps the verify
output for `Unknown`, because the exit status alone would not tell you. CI
runs it on the ubuntu runner, whose systemd is PID 1; a container booted
with `/sbin/init` works too, after `mount --make-rshared /`, which a real
boot does itself and Docker does not. Capture a command's output into a
variable before grepping it: `cmd | grep -q` under `pipefail` fails when
grep matches early and closes the pipe on a command that has more to say,
and the first run of that script fell over exactly there, on `auu enrol`.

**A reused connection does not handshake.** `http.DefaultTransport` keeps a
TLS connection made under earlier roots, so a test that changes the roots and
expects the next request to fail must `CloseIdleConnections()` first, or it
passes for the wrong reason.

**Test flag placement.** `parseArgs` exists because `auu read ID --json`
silently ignored the flag. When you add a command, at least one test passes a
flag after the positional argument.

**Test exit codes by type, not by string.** `asExit(err, &e)` and `e.code`.
The skill relies on 1, 2 and 3 meaning what they mean.

**Round-trip `--print-config`.** Print it, write it to a file, load it with
`--config`, compare. The HTML-escaping bug was only visible this way.

**The shell test harness bug.** A test script once passed all of a command's
flags as a single argument because it used `$*` where it needed `"$@"`, and
every test passed for the wrong reason. Use a function with `"$@"`.

## Concurrency, and tests that race

**Run the race detector on anything with a goroutine or a mutex.** The
limiter test spins 32 goroutines over shared and distinct keys. `make race` is
part of the definition of done, not an optional extra.

**A flaky test is worse than no test.** It trains everyone to re-run CI until
it goes green, which is the same as having no test at all. Every rule below
came from one that shipped.

**To know the server has reached a point, observe the server.** This one cost
two red CI runs. `blockingBody` was a request body that stalled until released
and closed a channel on its first `Read`, so a test could tell the request was
under way. But the *client* performs that read while writing the request, and
the client's own buffering, the kernel, and the scheduler all sit between it
and the server's handler. `TestInflightCap` waited on that channel and then
asserted the single in-flight slot was held: true on a quiet laptop, false on a
loaded runner.

The fix that did not work was to detect the lost race by asking whether the
*client* had received a response. `Do` returns an error on a broken connection
as well as a response on a refusal, so "no status recorded" conflated "still
stalled" with "never got anywhere", and the second failure blamed the cap.

What works is a raw socket: write the request bytes yourself, and have a
goroutine read the same socket, so "the relay answered" is a fact you observed
rather than an inference. `stallPost` in `internal/relay/stall_test.go` does
this, both in-flight tests use it, and `blockingBody` is gone. If a test needs
to know something about the server, it must observe something only the server
could have produced.

**When a test races something for a resource, it must tell losing the race
apart from the mechanism being broken.** Both in-flight tests now poll until
either the prober sees 503, which is the thing being tested, or the stalled
request is itself refused, which means the prober took the slot first and the
attempt proved nothing. The first is success, the second is retried. Crucially,
if the stalled request is still holding a slot *and* the prober gets through,
that is neither: it is the cap not working, and it fails. Get that distinction
wrong and a retry loop quietly turns a regression into a skip.

Prove it by breaking the thing on purpose. Delete the semaphore, run the test,
and watch it fail for the right reason. Both in-flight tests were checked that
way after every change to them, because a retry loop is exactly the shape that
can stop testing anything at all — and because the first retry-tolerant version
passed that check and still failed in CI for a third reason.

Give such a test a long deadline and let it be slow only when it is about to
fail. Fifteen seconds of polling costs nothing on a green run, because the
loop exits on the first correct answer; on a red one it is the difference
between a diagnosis and a coin toss.

**Timing assertions state what is claimed, not what this machine does.** The
timeout tests assert that the server does not wait for a gigabyte that will
never arrive; they allow it twenty seconds to notice. A tighter bound would be
measuring the runner, and a runner under load is slower than anything you will
see locally. The same goes for `HeapAlloc` assertions: the claim is "not
proportional to what was sent", so the bound is a small multiple of the cap and
not a precise figure, which would measure the garbage collector.

**No sub-second timeout in a test that starts a process.** Every row of
the after-hook test gave the handler and the hooks 200ms, and under the
race detector this test binary — which is the handler — takes longer than
that to start, so the handler was killed and the after hook, on the same
clock, was killed before it printed the status the test asked about. It
was one of the four things the first push of `auu serve` turned up in the
Windows job and the race job, and the one that reproduces here with
`-race`. A row that runs to the end gets ten
seconds; a row that is about the timeout gets two seconds against a handler
that sleeps thirty, since what it proves is the kill, not the clock.

**A test that starts a process which detaches gives it a way to learn the
test has gone.** A Cleanup runs only when the test binary ends on its own;
one that is interrupted, killed or timed out runs none, and a child in its
own session that was released is reached by no signal the test's end sends.
`auu agent start` under test is exactly that child, and three test agents
were found still running, one started on 22 September and two on 1 October,
from runs stopped by hand, holding test keys under a runtime directory
nobody would remove. Every helper-mode process now watches the test process
named by `AUU_TEST_PARENT` and exits when it is gone: `agentEnv` sets it,
and the serve tests set it on the environment they build by hand, since an
`auu serve` child left the same way once its test binary was killed.
`TestAnAgentDoesNotOutliveTheRunThatStartedIt` kills a run with an agent up
and holds it to going within ten seconds.

**Reproduce CI's contention before blaming CI, and reproduce the job that
failed.** Six copies of `go test -count=2 ./...` in parallel, four rounds, is a
closer approximation of a shared runner than one quiet run, and it is thirty
seconds. But `make test` and `make race` are different jobs with different
timing: the second CI failure here was in the race job, and the load test that
would have caught it is `for j in 1 2 3 4; do make race & done; wait`. Run the
job that broke.

**A server that refuses a TLS handshake cannot promise the client will hear
why.** `crypto/tls` gives up on the client's Certificate message, so the
CertificateVerify and Finished behind it stay unread in the server's receive
queue; closing a socket with data unread sends a reset, and a reset discards
whatever the peer has not read yet — which is the alert. An `http.Client`
makes it worse by writing its request before reading anything and returning
the write error. `TestARejectedCertificateFailsAsARemoteError` lost that race
four times in 240 under `make race`, and it was the third CI failure in the
race job. A test that wants the alert must serve the connection itself: let
the handshake fail, drain the socket, wait for the client to close, and close
only then, so that the close is a FIN. Read rather than send a request. The
product still races — see `reviews/IMPLEMENTATION_NOTES.md` — and the test
saying so in a comment is the point, not a defect in the test.

**Break the check, or you do not know what the test proves.** The additional
data in `internal/keyfile` binds the file's headers into the ciphertext, and
the test for it altered each header and asserted a refusal — and passed with
the additional data removed entirely. Every header is either a function name
the parser checks or a parameter of the key derivation, so an altered header
is refused whether or not it is bound in, and the test had been measuring the
other check the whole time. The binding still earns its place, for the header
somebody adds later that is neither; what changed is the test, which now
asserts that `aad` covers whatever the map holds, and the comment, which now
says which check actually fires. Running the suite against deliberately broken
code is the only thing that finds this class of mistake, and it takes a
minute.

**A break that passes anyway is not a proof, and is written down as one
that was tried.** "Serve never releases the split proxy's token" should
have left the token live for the twin test to find, and the test passed:
a `net.Conn` nobody references any more is closed by Go's finalizer, and
the proxy revokes on close, so the product covered the mistake by
accident of the collector's timing. That is worth knowing and worth
recording — it is in the notes — but it is not a break the tests catch,
and it was replaced in the break record by one they do (serve taking the
whole URL as the token), not counted.

**Know what the library does before you choose the break.** Go's reverse
proxy flushes a `text/event-stream` response immediately whatever
`FlushInterval` says, so setting the interval to zero did not make the
streaming test fail, and would have been counted as a proof of nothing.
The break that proves that test is the counting `ResponseWriter` without
`Flush` and `Unwrap`, which hides the flusher from the proxy and makes the
three chunks arrive together; and the test's clock starts before the
request, since a buffering proxy hands over the headers at the end too.

## Windows

The Windows job runs the agent, lockfile, store, keyfile, identity and
term packages whole and a named list of the CLI's tests, which is the list
to extend when a test with Windows-specific code is added. Its first run
of anything new is the proof; `GOOS=windows go vet ./...` on the ubuntu
leg is only the proof that it compiles. These are what it found.

**The line endings are the fixture's, not the machine's.** A runner with
`core.autocrlf` on checks a worktree out with CRLF, so the test that proves
a tracked edit does not survive a read-only worktree's move compared
`"the project\r\n"` against `"the project\n"` and said the edit had
survived. A repository a test makes sets `core.autocrlf false`, and so does
the clone an asker applies a patch in, so that both sides of `git apply`
agree; a byte comparison against a file git wrote is otherwise a
comparison against the runner's settings.

**A device name is a device on one Windows and a file on another.** The
first run of the name tests on `windows-2025-vs2026` made regular files
under `CON`, `nul.txt`, `com1.txt`, `CONIN$` and `CONOUT$` and resolved
`NUL` alone to a device, where the tests, written from Microsoft's
pages, had asserted every listed name a device to the OS and no file
made. The list is the union across versions and the assertion is one
way, as above; a test that creates under a device name asserts the
refusal or a regular file, never a device handed back as one, and
removes what it made. The same run answered an exclusive create over a
directory with `EISDIR`, where Linux and macOS answer `EEXIST`: a loop
that asks whether a name stands asks for both (`stands` in
`internal/auu/inbox.go`), and `TestADirectoryAtTheNameIsANameThatStands`
runs there to show the file going beside the directory.

**A lock's pid cannot be read while it is held on Windows.** The serve lock
is a handle opened with no sharing, which is what stands in for `flock`
there, so nobody can open the file again while it is held: not the second
process that wanted to read the pid for its refusal, and not the holder
that wanted to write it. The sentence says one less thing on Windows, and
the test asks for the pid only where it can be had. The lock's sharing mode
was left alone: it is a primitive the agent and every fetch depend on, and
a pid in a sentence is not worth changing it for.

**A test about a signal, a process group or a file mode runs off Windows,
and says so.** There is no process group to signal, Go's `FileMode` on
Windows is made from the read-only attribute and says nothing about 0600,
and a `Stat` mode check there is a check of nothing. Skip with the reason
in the sentence, as `TestAnotherUidIsRefused` does for peer credentials,
rather than loosen the assertion for every platform.

## The container suite

`make e2e` (`docker/testing/`) runs the two guides in four containers and
then a matrix of what goes wrong in the wild, and writes a report of what
each party saw. These rules came from getting it to run.

**A row pins the sentence the code prints today, and the report judges it.**
The suite is about how the programs speak to a person who did something
ordinary and wrong. A row whose reporting is poor asserts the poor sentence
exactly and marks itself `gap`; the suite stays green and the report says
what is missing. A row that guesses at a better sentence than the code has
fails for the wrong reason and proves nothing.

**The survey is a hypothesis; the run is the fact.** The plan's rows were
written from reading the code, and the first run corrected several of them:
the relay was expected to refuse a bundle for another host, and it started;
the admin file's reload was expected in the log, and it is silent; the
"administrators loaded earlier" it keeps on a stat failure were expected to
be the ones it loaded at start, and they were none. Write a row as
`observe` first, run it, and then pin what it saw.

**Run every fault row once with the fault disabled.** `AUU_E2E_NOFAULT=1`
turns each fault helper into a no-op. A row that still passes has an
assertion that does not depend on the fault; for a row whose subject is
that nothing is said, that is the finding, and for any other row it is a
bug in the row. The notes list which rows pass without their fault and why.
The row about a deleted database row called `sql` directly instead of the
guarded helper and "passed" the check by not disabling anything.

**A file that crosses the host loses its owner.** `docker cp` of a file to
the host gives it the host user's uid, and copying it back gives the relay
a file it cannot read: every row after the first restore failed with
`storage error` for a fault that had already been undone. Back up as a tar
stream (`docker cp CONTAINER:PATH -`) and restore from it (`docker cp -
CONTAINER:DIR`); the tar carries uid, gid and mode.

**A timestamp is a clock's opinion; a line count is a fact.** `docker logs
--since` let a `serving` line written before a restart satisfy a check
about the restart, and made a silent reload look logged. The harness marks
the log by its line count and reads what came after the mark.

**The log line comes before the socket.** The relay logs `serving from an
auu-ca bundle` a moment before its listener answers, and the first command
after a restart got `connection refused`. After the line, probe the port
(`bash -c 'exec 3<>/dev/tcp/HOST/PORT'` from a container) until it opens.

**Cleanups run last first, so order them by what they check.** Re-pinning
the administrator's anchor was registered after restoring the bundle, so it
ran before it, while the aged relay still served, and `anchor pin` refused
because the relay's anchor did not match. Register the cleanup that checks
the relay before the one that puts the relay back.

**A fault that stops the relay takes `exec` with it.** `docker exec` needs a
running container; `docker cp` does not, and `docker compose run --rm
--no-deps` reaches the volumes. Files in the container's own layer, such as
the credential under `/run`, are only reachable by `docker cp` once it has
stopped.

**Without `-i`, `docker exec` gives the command end of file at once.** That
is what a script that gives no input looks like, and it is the right
default. The one prompt that reads a line, `quarantine trust`'s local name,
took its fallback until stdin was attached, and every row after it looked
up a peer called `peer-28ea0351`.

**A burst is concurrent.** Thirty-one sends one after another never met the
thirty-a-minute limit: each took about a second and the bucket refilled at
half a token a second. Forty-five at once did.

**Guard a bundle-shaped file by its keys, not by the first hex string.** The
row that edited an attachment's digest found the first sixty-four hex
characters in the file, which were the sender's fingerprint, and the
extract succeeded; nothing re-verifies a stored message. Navigate the JSON.

**From v0.16.0, the suite runs against the previous release too (D41).**
v0.15.0 is the first kept version of the wire, and v0.16.0 is the first
release the rule runs for. Family O in `docker/testing` builds the
previous release beside this tree: `run.sh` makes a local clone of the
repository at the release's tag, fetching nothing, so that Go stamps the
binaries with their version as it stamps any tagged build, and the image
builds them in a stage of its own beside this tree's. Its rows are an old
recipient reading a new message to several, as an envelope and as a
stream; a new sender posting through an old relay; and an old sender,
with the old tools, on a new relay. Each row checks each old program's
version before it relies on it, so a row cannot pass against this
tree's binary by mistake. A promise that an older build ignores or refuses by name what a
newer one adds is tested by the older build itself, never by a fake of
it; there is no fake old relay in the tree, and this is why. Each
release moves the tag in `run.sh` to the release before it.

**A known section comes with the tests that hold its rule on every path,
and the first one is the worked case.** The `recipients` section and its
two numbers were tested so, and a later section is held to the same. The
rule runs where the sealer writes the section, before anything is signed
(`TestSealManyRefusesBeforeItSigns`, which counts the signatures), and
the manifest builder refuses the same lists and hands back nothing
(`TestBuildManifestManyRefusesWhatSealManyRefuses`); on both sealed paths
once the signature has verified, the envelope's `Open`
(`TestAListThatBreaksTheRuleIsMalformedAtOpen`) and the manifest's
`OpenManifest` (`TestAListThatBreaksTheRuleIsRefusedOnTheStreamPath`),
each with its twin proving that a list under a signature that does not
verify is refused for the signature and not the list
(`TestAnUnsignedListIsRefusedForItsSignature`,
`TestAnUnsignedListOnAStreamIsRefusedForItsSignature`); and at the
store's `Load`, as the record rule, in `TestLimitStoredRecordShapes`. The
size is checked before the strict decode, and the test feeds data over
the cap whose last byte is not JSON, so a decode that ran first would say
something else (`TestTheSizeIsCheckedBeforeTheDecode`). A count is held
at its edges, 0, 1, 32 and 33, and at the type's extremes, beside the
forms a JSON number may not take (`TestTheRuleTakesAListAndRefusesWhatBreaksIt`,
`TestLimitRecipientNumbers`). A request's section is held at the relay
through the real route, before anything is stored or charged where the
route allows it, with the budget the refusal did not spend shown spent by
the next request (`TestAStreamOpenIsHeldToMaxRecipients`), and after the
charge on the forward route, where every decode is, with the cost shown
(`TestAUsersForwardIsHeldToMaxRecipients`,
`TestARefusedForwardCostsAPostAsAMalformedOneDoes`); a relay that must
not read it is shown not to (`TestACouriersRecipientCountIsNotRead`), and
the log is shown not to carry it (`TestTheCountIsNotLogged`). An answer's
section is read by the client absent, present, outside its rule and of
another shape (`TestTheHealthAnswersMaxRecipients`). And the previous
release reads it, in family O, since only the old binary can say what the old binary does.

## Manual verification

**Run the thing.** Every feature was exercised against a real `auu-relay`
process with real `auu` and `auu-admin` binaries before completion was
reported: the 507 message by peer name, the 429 sleep of exactly the seconds
asked for, the admin file granting and withdrawing access without a restart,
the audit log carrying every action. The scratchpad directory exists for this;
do not do it in the repository.

**Record what you observed, in numbers.** "100 posts at defaults: 30
accepted, 70 refused, every `Retry-After` 2s" is a record. "Rate limiting
works" is not. The record goes in `reviews/IMPLEMENTATION_NOTES.md`.

**Do not claim a test exists, a count, or a result you did not check.** Count
tests with `go test ./... -list '.*' | grep -c '^Test'`. If manual
verification needs something you do not have — a public host for a Let's
Encrypt run — say that it is outstanding and what it needs, and record it.

## Before you report completion

- `make vet test build` clean.
- `make race` clean, run several times: a test that passes four times in five
  is a failing test.
- `go test -count=3 ./...` clean, and for anything touching sockets, goroutines
  or the clock, several copies in parallel: `for i in 1 2 3 4 5 6; do go test
  -count=2 ./... & done; wait`. CI is slower and more contended than your
  machine, and that is where the ordering assumptions surface.
- Every test the specification lists exists; grep for each.
- Every range check is tested on both sides of both edges, one step apart.
- Every signed parameter is tested at MIN, MAX, MIN+1, MAX-1, zero and minus
  one, plus the input that makes each subtraction or negation land on MIN.
- Every verify, open or integrity-checked decode has a negative test that
  flips one bit in each structural region and asserts the specific error.
- Every cryptographic round trip runs over random input and logs its seed.
- Every length the peer can state — body, encoded field, count, array,
  limit — is refused over its cap before anything is allocated from it, and
  the test proves the order by which error came back.
- `go.mod` and `go.sum` unchanged, or the change is the one scoped exception.
- The README's and the `docs/` documents' tables agree with the code: flags,
  config keys, defaults, commands, response codes. Check mechanically, not
  from memory.
- Departures from the specification are in `reviews/IMPLEMENTATION_NOTES.md`
  with reasons.
- Nothing under `reviews/`, `bin/` or `.claude/settings.local.json` is
  staged.
- The rules review has been run over the staged diff (the `rules-review`
  skill) and its record says ready: every rule the change touches named
  with its line and the test that shows the value, and a reason for each
  family that does not apply. The commit hook refuses a commit without it,
  and a reviewer refuses a request without it.
