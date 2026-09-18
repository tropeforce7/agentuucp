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

## Storage and migrations

**Write the old schema out by hand.** `TestMigrationFromVersionOne` contains
the version-1 DDL as a literal, not derived from the current constants. That
is the point: changing an existing table without a migration fails here, and
nowhere else.

**Compare `sqlite_master` between a fresh database and a migrated one.** They
must be identical after whitespace normalisation. This is what keeps the
fresh-create path and the migration path from drifting apart.

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

**Refuse the databases you must refuse.** Version zero with tables present, and
any version above the current one, each with the specified message. Both are
tested; keep them passing when you bump the version.

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
