# Security model

What the relay stores, what it sees, what protects a message, and the wire in detail. Every claim here is meant to be checkable against the code; if one is not, that is a bug in the claim.

## 1. Security model

**What the relay stores.** The recipient's fingerprint, the size of each
message, when it arrived, and the channel it was posted to. That is all: the
sender's identity is inside the ciphertext, so the stored rows do not say who
wrote anything. The channel is one label per message, from a list the owner
wrote and published to every sender they admit; it is there because the
relay routes by it, refusing a post to a channel that does not exist or is
not open before the message is stored, and the owner chooses what the labels
say. The message itself is a file beside the database, which an operator can
list, count and delete but not read. Every value the relay puts to that
database — a fingerprint, a channel name, a token id, a reason — goes as a
query parameter, never into the text of a query, and a test
(`internal/sqlshape`) parses the tree and fails on any query whose text is
not a constant.

Since a channel keeps its mail by default, that ciphertext now stays until
its owner removes it rather than until they read it. The relay learns
nothing more from the wait: it never knows a message was read, because
nothing tells it — a fetch is a `GET` of the mailbox, and the `DELETE` that
follows says only that the owner is finished with it, whether that is a
second later or a month. What it costs is room, which the per-mailbox
limits bound.

One table is an exception, and it is worth stating: while a stream is being
uploaded, the relay holds a row naming the *sender* as well as the recipient.
It has to, because only the sender may append to their own upload and the
reservation must be charged to somebody. That row lives for the length of one
upload and is deleted when the stream completes or is abandoned — it is the
only place the relay writes down who is sending something, and nothing survives
it. While it lives, the reservation counts against the recipient's quotas
and the relay's as though the stream were already queued, for an envelope
posted beside it as much as for another stream: one arithmetic answers
both, so neither can be filled into the other's reservation.

**What the relay sees.** More than it stores, and this is worth being plain
about. Posting is authenticated, so at the moment a message is accepted the
relay knows which identity is writing into which mailbox. Its access log
records exactly that unless you set `access_log: "minimal"`, and rate limiting
keeps the verified fingerprint in memory for as long as a bucket lives.
Anybody holding the logs of a `full`-mode relay holds the social graph. Nothing
is written to the database, and no limiter key is ever written anywhere. The
channel a message was posted to is the one thing about a message's content
the relay learns beyond its size: it is written to the row, served in the
owner's own listing, and recorded in the access log under neither mode.

A listing held open (`wait`) tells the relay nothing it did not know: it is
the owner's own listing, answered later. A directory watch (`peers`) tells
it which peers the watcher may post to, which the directory fetch the
watcher made first had already told it, and nothing about a peer who has
not admitted the watcher, since such a peer is dropped before anything is
held. Neither reaches the access log: the query string is not logged under
either mode. And there are no delivery receipts, and cannot be: the stored
row has no sender, so nothing ties a message being collected to the person
who posted it, and building that would mean recording the sender on every
message, which is the social graph the relay is built not to hold.

**What the network says reaches a terminal escaped.** A relay is trusted
with routing and nothing else, and what it sends back is read on a
terminal: a display name in a listing, a machine's certificate label, and
the sentence it attaches to every refusal, which every user of every relay
reads on standard error. Each is made printable before it is shown — a
name and a label are held to a rule that leaves no control or format
character in them, and a sentence has every character a terminal would
obey rather than show escaped the way Go quotes a string, where the error
is made rather than where it is printed, so no command can forget. What a
peer writes is held to the same standard twice over: a subject, a text
and an attachment name are refused at open, on both paths, if they carry
a control character (a line break and a tab in the text excepted), a
format character, a private-use character or a line or paragraph
separator, and every print of one — the inbox listing, `read`,
quarantine, watch, serve's console lines, completion — escapes it all the
same, for a record from before the rule; sender names, which come from
this machine's own peer list, go through the same escaper. `auu-admin`'s
listings hold the relay's enumerated words — a registration mode, a
certificate mode, an allow state, a token's use and state — to the set
the protocol defines, refusing the answer whole otherwise, and escape its
free text (a public URL, an uptime, an access-log mode, a block's reason,
a note); a pasted token's relay and note are escaped when it is described;
and the key proxy's log line escapes the path a caller sent. The
same treatment covers a name from a relay older than the rule, and
`auu-admin`'s confirmation before it removes a mailbox, which prints the
name at the one moment an administrator is reading carefully. And what
the relay lists is checked for shape before it is used: every fingerprint,
serial and token id in an answer is held to its rule as it comes off the
wire, a lifetime it reports in seconds is bounded before anything
multiplies it, every count it reports is zero or more, every message id
one or more, a parameter set one of the three, and an upload's offset a
byte count, so an answer with a two-byte fingerprint or a negative queue
is refused whole as malformed, naming the field and the relay, rather
than sliced by a command that expected sixty-four characters or seeked to
by one that expected an offset. Every integer that enters the program
from outside — a field in a JSON shape, a number parsed from text, a
length read from four bytes, a flag — has a row in `internal/limits/ledger.txt`
saying the range the code holds it to and the test that takes it to the
edge and one step past; the test beside the ledger walks the tree and
fails on a site with no row.

**What protects a large message.** The same HPKE ciphersuite, in its stateful
multi-shot mode: one context for the whole stream, one sealed chunk at a time.
The context advances a nonce on every chunk and only on a chunk that opened, so
reordering, duplication and mixing chunks between streams all fail without
anything being added. The final chunk is sealed under a different label, which
is what makes truncation a decryption failure rather than a short file.

A stream from somebody who is not in `authorized_peers` is never downloaded.
The receiver fetches the 1124-byte header and the signed manifest, sees who it
is from, and stops — the body stays on the relay until a person runs
`auu quarantine trust`. A stranger cannot make anybody pull two gigabytes.
What they can make a receiver keep is the manifest record in quarantine,
and the first chunk it came in is capped at 1 MiB, so the disk they can
spend is bounded by that.

**What protects a message.** Every message is sealed with HPKE (RFC 9180) in
single-shot mode, straight from the standard library's `crypto/hpke`. The
ciphersuite is MLKEM768-X25519, better known as X-Wing, with HKDF-SHA256 and
AES-256-GCM. X-Wing combines ML-KEM-768 with X25519, so an attacker must break
both: traffic captured today is not readable by a future quantum computer.
Each message carries a fresh encapsulation, so one compromised message does
not expose the others.

The recipient's fingerprint is bound into the HPKE `info` string. An envelope
that is re-addressed to someone else cannot be opened by anyone, including its
original recipient.

**What proves who sent it.** An Ed25519 signature over the inner record, bound
to the recipient's fingerprint. A peer cannot forward a message they received
and pass it off as one written for someone else. The claimed sender fingerprint
is recomputed from the key material in the message before the signature is
checked, so `from` cannot be decoration.

**What client certificates add, and what they do not.** A second credential at
the transport layer, per machine, so a relay can tell one of your computers
from a copy of your `~/.auu` somewhere else, and revoke one without touching
your identity. A stranger presenting a certificate the authority did not
issue is refused at the handshake; one presenting none completes it and is
refused at every mailbox route and at the key lookup. The routes open
without one are the trust anchor, the health check and enrolment, which a
new machine needs before it has a certificate, and administration, whose
authority is the file on the relay's host and not a certificate.

They add nothing to the confidentiality or the integrity of a message: HPKE and
the Ed25519 signature do that end to end, and would still do it if the whole
transport were plaintext. They are ML-DSA, at the parameter set the
authority was created with (`auu-ca init --mldsa`, 44, 65 or 87; 65 by
default), so the client's authentication to
the relay is post-quantum, as the key exchange already is; the relay's own
certificate now comes from the same private authority, so it is
post-quantum too — every certificate in the chain is ML-DSA.

The relay holds the private key of the authority that signs them — the first
signing key a relay holds, and a deliberate exception to the rule that it holds
none. What a stolen copy would buy an attacker is the ability to mint a
certificate for any fingerprint, which still gets them nothing without that
identity's signing key, because every request needs both. What it would not buy
them is any message, any identity key, or any token.

The relay also learns how many machines an identity uses and what each one
calls itself. That is operational data it needs in order to revoke one of them;
it is not who talks to whom, and `access_log: "minimal"` is unaffected.

**Which algorithms, and what stops them being downgraded.** An identity is
built from a *suite*: today the only one is Ed25519 for signing and
MLKEM768-X25519 for receiving. `auu id` names it and `auu peers ls` marks any
peer who is not on it.

There is no negotiation, and that is the point. **A fingerprint is a hash over
the bundle, and the bundle says which suite it is**: the original suite by
its length alone, since its bundle predates there being a suite byte, and
any other by a leading byte that makes it a different length again. So
there is no such thing as "the same sender on a weaker suite": a different
suite is a different bundle, a different fingerprint, and therefore a
different person — one your `authorized_peers` does not know. Every place
a bundle arrives from the network checks it. `auu lookup` refuses a bundle whose fingerprint is not the
one asked for, or does not begin with the short id asked for, so the relay
does not get to decide who a fingerprint belongs to; opening a message refuses
a `from` that is not the hash of the bundle beside it, and opening a
stream's manifest does the same. An attacker who wants you to accept a signature they can
forge has to persuade you to add a new peer, out of band, by hand.

Nothing negotiates at the transport either. Every connection this project
makes or takes — a client's requests, the anchor fetch that comes before a
new user has anything to verify with, and the relay's own listener on both
its branches — is pinned to TLS 1.3 with `X25519MLKEM768` as the only key
exchange, and refuses less; there is no option to relax it, since every
relay is built from this tree and there is nothing older to meet. So a
recording of who talked to whom made today is protected by the same hybrid
as the messages inside it. A relay that will not make that handshake — one
from before v0.7.0, or one behind a TLS terminator that lacks the hybrid — is
named by the client in one sentence rather than by Go's alert. A relay run
with `tls.mode: "off"` behind somebody else's terminator is that
terminator's TLS, not the relay's, and this says nothing about it.

**What an administrator sees.** The list of mailboxes: fingerprints, display
names, how much each is holding, and how many channels each has defined —
the count, never the names, which are the owner's to publish to their
senders. Never a message: an administrator has
exactly the same view of the ciphertext as the relay does, which is none. That
list is inherent in running a relay, which is why the file naming
administrators belongs to whoever runs the host and to nobody else.

**Enrolment tokens.** Signed by the issuing administrator's own identity key,
so the relay holds no new private key material and removing an administrator
from the authorized file invalidates every token they issued. A token must also
be registered with the relay before it can be redeemed, which is what makes
revocation and single use real rather than hoped for. Tokens are bearer
credentials: send them over TLS, and the relay never logs one. The relay does
not record which token created which mailbox — that link appears once in the
operator's audit log and nowhere in the database, because a permanent table of
who invited whom is a social graph of a different kind.

**The allow list.** Owner-signed, like the channel directory: `auu allow
push` signs the list of who may post to you with your identity key, and the
relay verifies the signature against your registered key before storing
it and again on every post, with no cache. A row edited in the relay's
database therefore refuses every sender rather than admitting one — a
sender is told what a refused sender is always told, your own listing says
`broken`, `auu inbox` says so, and your next `auu allow push` is the whole
repair. A row with no signature is broken too: a list converted from
before v0.5.0 by the relay's upgrade, and a signed row with its signature
removed, both refuse every sender at once — there is no state in which the
relay honours a list it cannot verify, so an upgrade from before signed
lists leaves a restricted mailbox closed until its owner pushes, and `auu
inbox` tells them so on every fetch. Your own machine also remembers that
it pushed a signed list, and says so if the relay's row has gone
altogether. What this does not cover is root on the relay's host, who can replace the relay itself, which is where *What
is not protected* below draws the line: the signature moves the bar from
editing one table to replacing the binary.

**Where trust comes from.** `authorized_peers`, and nowhere else. The relay's
key lookup endpoint is a convenience for typing accuracy; it is not a trust
anchor, and `auu lookup` deliberately refuses to add anyone. Confirm
fingerprints with people directly. The one identity trusted without an entry
is your own: a message you sent yourself is opened, verified and delivered
like any other, and the relay accepts it for your mailbox whatever your allow
list says. That is also the one message a relay can see is from you: sender
and recipient are the same authenticated identity, which a `full` access log
records as such.

**What is not protected.** The relay knows who talks to whom, as above. It can
drop messages or refuse service. It cannot read, forge, or redirect them. An
attacker with root on the relay's host is outside this model altogether:
they can do anything the relay can, including replacing it, and the relay
cannot defend itself from the machine it runs on. What such an attacker still
cannot do is read or forge a message, and *Keeping a relay private* in
`relay.md` says what keeping the host secure means.
Compromise of your `identity.json` gives an attacker everything: your mail,
and the ability to write as you. With a passphrase set (see *Encrypting your
keys*) the file holds only your public half, the keys are ciphertext under a
passphrase stored nowhere, and a copy of the home yields them only to somebody
who also has the passphrase; what a copy still yields, passphrase or not, is
the mail in `inbox/` and `sent/`, which is stored open.

**The receiving agent.** A signature says who wrote a message. It says nothing
about whether the contents are safe. Inbound text and attachments are treated
as data by the skill, never as instructions, and unknown senders never reach
the inbox at all. Nothing arrives unasked: mail moves only when a command
fetches it — `auu inbox`, `auu wait`, `auu watch --fetch`, or each round of
`auu serve`.

**What an induced action can do.** The cryptography authenticates whatever
the key signs, so the attack that matters against an AI is not breaking a
message but talking the AI into originating one: while the key agent is
unlocked, any process running as the user can have it sign, and a message
built to subvert an AI could have it send as the person. No confirmation
the agent asked for in-band would help, since the same process answers it.
So an unlock has a scope, and the agent decides by the domain string at the
front of what it is asked to sign — every construction here has one, and a
relay request its method and path against the relay's route table — never
by who asks. A plain `auu unlock` is receive scope: the agent opens mail,
signs the transport, and signs what lists, fetches, watches and
acknowledges, and refuses to sign a message, a stream's manifest, a channel
directory, an allow list, a token, or any request that posts, uploads,
registers, pushes or administers; anything it does not recognise is
refused too. `auu unlock --send` — the passphrase again, ten minutes by
default — is everything, and then back to receive. An induced action in
receive scope can therefore fetch mail and acknowledge it, which is to say
delete it from the relay, and renew this machine's own certificate — which
the relay issues to the signing identity's fingerprint and to no other, on
the live certificate it then retires, with no token and for no other
machine, so it is maintenance and not an act — and nothing more; in a send
window it can originate as the person, which is why the window is short
and typed for.
This does not reach a home that was never encrypted, whose keys are files
any process can read, nor one whose passphrase is in a file, which the AI
can read too. The one accepted exception is `auu serve`: an expert
originates unattended by design, to the channel it serves, and is unlocked
with `--send --ttl 0` on a machine that is nobody's desktop; serve refuses
to start under receive scope and says so.

## 2. The wire, in detail

What the relay stores for one message is three fields, and a fourth on a
named channel: `v`, the format version; `to`, the recipient's fingerprint;
`ct`, about 4 KiB of ciphertext for a short message; and `ch`, the channel,
omitted for the default one. Sealed inside `ct`, where the relay cannot
read a byte of it, are the Ed25519 signature, the sender's fingerprint and
public keys, the subject, thread, message id and time, the text, and any
attachments. Sign-then-encrypt, so the signature is inside the box: the relay
can see that somebody posted to Bob, and cannot see that it was you.

The message id, the thread and, on a reply, `in_reply_to` are each a
message id: 32 lowercase hex characters, the id of the message that opened
the thread or that is being answered. That is a rule of the format, not a
convention. A record whose id, thread or `in_reply_to` has any other shape
is refused when it is opened, kept under `damaged/` as malformed and
acknowledged, and `auu send --thread` refuses one before anything is
sealed; a stream's manifest is held to the same rule.

**Nothing the network names is a path until its rule has run.** Eight
things that arrive over the wire become part of a path somewhere, and each
has one rule and a named place it runs, before the value goes near a
filesystem or a database; a signature proves who wrote a value, not that
the value is safe. In order: a *fingerprint* in a URL names a mailbox's
directory on the relay, and the relay checks it is 64 lowercase hex before
it reads the signature; an *upload id* names an upload's file, checked as
32 lowercase hex before the row is read; a *token id* is checked the same
way before the store is asked; an *attachment name* becomes a file on the
receiver, and is a base name with no separator and no `.` or `..`, distinct
from the message's other names where case does not count, not a Windows
device name (`CON`, `NUL`, `COM1`, with any extension or none) and not
ending in a dot or a space, since the receiver may be on Windows and a
sender cannot know; checked when a message is opened and, for a stream,
when its manifest is, and passed through `filepath.Base` again at the
write; a *channel name*
becomes a directory under an expert host's serve directory, and is held to
the directory format's rule at the relay for every post, at every push of
a directory, and at the client's `--channel`; a *relay host* names the
authority's record of the relay, and `auu-ca` holds it to the shape of a
DNS name or an address before any record is filed; a *message id* names
the record's file, and is a message id at open, in a manifest and at the
store; a *thread id* names a directory and a worktree under an expert
host's serve directory, and is a message id at open, in a manifest, and
checked again by `auu serve` before it is joined onto anything. One test
walks every one of them with `..`, `../x`, `a/b`, `.`, the empty string
and a NUL, and a new place that turns something from the network into a
path gets its row there first. Behind that table is a ledger,
`internal/fileopens/ledger.txt`, with one row for every call in the tree
that opens, makes, removes, renames, lists or runs something by a path,
saying whether the path is the program's own, the operator's, derived
from something the program read back, or from the network with the rule
and the point that check it; its test parses the tree and fails on a call
with no row, so a ninth component would be found before it was a finding.

### 2.1 The round trip

With keys already swapped, in person or over something you both trust:

1. Your agent runs `auu send --to bob --attach Missing.java`.
2. `auu` signs the record, then seals it.
3. `auu` sends `POST /v1/mailbox/{bob}` to the relay.
4. The relay answers `200`, queued. It holds ciphertext, cannot open it, and
   does not know it was you.
5. Minutes or days later, their agent runs `auu inbox`.
6. Their `auu` sends `GET /v1/mailbox/{bob}`.
7. The relay answers with a listing of sealed envelopes.
8. Their `auu` opens each one, verifies the signature, and checks that the
   sender is a known peer.
9. Their `auu` sends `DELETE` to acknowledge it, and the message is gone from
   the relay.
10. The question and its files are handed to their agent, marked as untrusted
    input.

The `DELETE` at step 9 is the interesting one: the message leaves the relay
only after it is safely on local disk. Crash anywhere in between and you fetch
it twice, never zero times. It happens at the fetch only for a channel you
have set to `off` with [`auu channel keep`](client.md#14-channels); by default a channel
keeps its mail, so the fetch leaves it queued and the `DELETE` is what
[`auu rm`](client.md#15-receive) sends when you remove it.

The answer at step 7 lists what is after this machine's cursor and, beside
it, how many messages the mailbox holds in all (`queued`). The count is
routinely the larger, since by default a channel keeps its mail, which is
counted but not listed after the cursor; the client subtracts what this
machine deliberately left on the relay before it judges the rest. When the
list is empty and the count still exceeds that, the cursor is past mail
— set by hand, or copied from a machine that had fetched further — and `auu
inbox` says so, with the count, the cursor file to delete and the `auu inbox
--relay NAME` to run after, and exits 5 without acknowledging or writing
anything. A relay from before the field omits it, and the client says
nothing. Each message listed says which channel it is under (`channel`),
always, `default` included; a listing without the field is from a relay
from before channels, and the client files by the sealed record alone.

Two routes carry a mailbox's channel directory, the signed list of named
sub-mailboxes an owner defines: the owner pushes it with `PUT
/v1/mailbox/{fp}/channels` as the document bytes and the signature over them
(`document`, `signature`), and the relay verifies the signature against the
registered key before storing either, answers `401` for one that does not
verify, `400` with the rule broken, and `409` for a directory issued no later
than the one it holds, naming when that was issued. The relay never bounds
`issued` against its own clock, so an owner who signs one far in the future
locks their own other machines out of pushing until they push a later one,
or deregister; only the identity key can do that, to itself. Anyone the allow list
admits fetches it with `GET /v1/mailbox/{fp}/channels` and gets the same two
fields back verbatim, to verify against the key they hold for the owner; a
sender the allow list refuses gets the refusal a post would, and learns
nothing about channels; a mailbox whose owner has pushed none answers `404`
with `no directory: the mailbox has the one channel, default`. The owner's
own fetch adds `queued`, how many messages wait under each channel; nobody
else's does.

The allow list travels the same way. `PUT /v1/mailbox/{fp}/allow` carries
three fields: `document` and `signature`, the list as the owner signed it
under its own domain, and `allow`, the same senders as a plain array, which
a relay from before signed lists reads and one from after ignores — it is
still sent so that an old relay is told the list rather than an empty one.
The relay verifies the pair against the registered key before storing
either, answering `401` for a signature that does not verify, `400` with
the rule broken, `409` for a list issued no later than the one it holds,
and `400 this relay needs a signed allow list; update auu to v0.5.0 or
later` for a body with the array alone, which stores nothing. The owner
reads it back with `GET /v1/mailbox/{fp}/allow`: the pair verbatim and
`state`, one of `signed`, `none` (never pushed; any registered sender may
post) and `broken` (does not verify, a row with no signature included;
every sender refused). The owner's own mailbox listing carries the same word as
`allow` on every answer, and a relay from before it omits the field.

A message posted to a channel names it in the clear: `ch` on the outer
envelope at step 3, `channel` on the request that opens a stream. The relay
reads it after the allow list has admitted the sender and before anything
is stored or charged to the recipient's mailbox — the sender's own budgets,
posts a minute and bytes an hour, are spent before either check, so a
refused post costs the relay little, and a sender the list refuses learns
nothing about channels — and refuses `404 no such channel "x"` for a name the directory
does not hold (`default`, for a mailbox with no directory) and `403 channel
"x" is not open: opens T` or `closed T` for one outside its period, judged
by the relay's clock with both edges inclusive. The sealed record and the
signed manifest carry the same name, so a message the relay filed elsewhere
is found out on opening. Absent means `default` everywhere, and a message
sent with no channel is byte for byte what it was before channels.

The sealed record carries a time, and it is the sender's word alone: it is
shown, labelled as theirs, and it orders nothing. A thread's order is the
receiver's — when each message arrived here, then the relay's counter —
so a peer cannot stamp a message into being the latest on a thread and
draw every reply by thread to it. The one bound on the stamp is the
future: a message may be old, since it was stored and forwarded, but one
stamped more than the request skew (five minutes) past the receiver's
clock is refused at open as malformed, on the envelope and on the
manifest alike.

The listing at step 7 takes three more parameters, all optional. `wait=D`
asks the relay to hold the answer until a message arrives after the id asked
from, or `D` elapses, and then to answer the ordinary listing. A relay holds
for at most 60 seconds, clamping a longer `D` rather than refusing it, and
one already holding as many listings as `max_waiting` allows, or two for the
same identity, answers at once instead: the hold degrades and never refuses.
`peers=FP:ISSUED,...` names peers whose channel directories the caller is
watching and the issue time it holds for each, in Unix nanoseconds; a push
that replaces one of them wakes the hold, and the answer names in
`directories_changed` every watched peer whose directory is issued later
than the caller said. A peer the caller may not post to is dropped without a
word — never named, never woken on — since the directory fetch the caller
made first has already told it `403`. `stubs=1` answers every row without
its `envelope`, for a caller that wants the ids and nothing else — which is
what checking whether mail it left on the relay is still there needs, and
what stops a mailbox of such mail being downloaded again on every check. A
relay from before any of the three ignores it and answers as it always did,
and a listing that asks for none of them is byte for byte what it was.

A large message changes step 7 only. Instead of arriving with the rest of the
mailbox, it is listed as a stream and its body is fetched separately, in
pieces, straight to disk — which is what lets a two gigabyte attachment cross a
relay that never holds more than a chunk of it.

A message that does not open at step 8 — it did not decrypt, it names another
recipient, its sender does not hold up, or it is not an envelope — is nobody's
to read, and leaving it queued would block the mailbox, so it is acknowledged;
but first its bytes are kept under `damaged/` in your home with the cause in a
word, the warning names the file and says to ask the sender to send it again,
and `auu inbox` says how many are there until you remove them.

A message that opens is filed under the channel it was sealed for, after that
name has been checked against the one on the outer envelope and the one the
relay listed it under. A disagreement is a message the relay filed elsewhere:
it is kept under `damaged/` with the cause word `misfiled`, the warning says
`relay message N was filed under "a" by relay.example.com but is sealed for
"b"; it was kept as PATH`, and it is acknowledged like the other kept
messages, so the mailbox is not blocked. A relay from before channels lists
no channel, and the sealed record alone decides.

### 2.2 A large message

Above 64 KiB, `auu send` stops building one envelope and builds a stream. It is
one HPKE context and a run of sealed chunks: the manifest first, saying what
the message is and what each file must hash to, then the file bytes.

On the wire a stream is, in order: `enc`, the 1120-byte X-Wing encapsulation;
`len0`, four bytes saying how long the manifest is; chunk 0, sealed, holding
the signature and the manifest (subject, text, file names, sizes and SHA-256
hashes); then file bytes in sealed chunks of 63 KiB; and a last chunk sealed
under the label `final`, after which nothing may follow. What a manifest may
name is what a message may: each file name a base name, and no two of them
one file where case does not count, since the receiver's disk may fold
case; both ends apply the rule, the sender's before anything leaves. A pair
the rule cannot foresee that the receiver's disk still spells as one — two
Unicode normalisations of one name, on APFS — is refused where the file is
opened, as the manifest's fault, so the stream is kept under `damaged/` and
acknowledged rather than met again at every fetch.

Three things fall out of that shape:

- **The last chunk is sealed under a different label.** Cut a stream short and
  the chunk the receiver expects to be the last one will not open. Truncation
  is caught by the cipher, not by a length field somebody could lie about.
- **Chunk 0 is enough to decide.** A receiver fetches 1124 bytes plus the
  manifest, learns who sent it and how big it is, and only then agrees to
  download the rest. A stranger cannot make anybody pull two gigabytes.
- **Nothing is ever held whole.** The sender seals a chunk at a time, the relay
  writes a request at a time, the receiver decrypts a chunk at a time and
  writes it straight to a file. Sending a 2 GB file costs about 20 MiB of
  memory at each end.

An interrupted upload resumes: the sealed copy stays in `outbox/` and
`auu send --resume` carries on from the byte the relay already has. That is
also why sending seals to disk first — the nonce counter inside an HPKE context
only goes forwards, so a chunk that was lost could never be sealed the same way
twice. An upload has an expiry, `upload_ttl` on the relay, and past it the
append, completion and abort routes all answer `410`, naming when it expired
and saying to open again, with the upload and its reservation gone; the
resume then opens a new upload for the same sealed bytes rather than
failing. A resume that names an upload the relay no longer holds at all is
answered `404`, on the append as on the rest. A relay whose disk fills part way through is the same case: it answers
`507`, keeps what it has, and `auu send` says the upload is kept and to resume
it when there is room.
