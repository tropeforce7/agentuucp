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
list, count and delete but not read.

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
it.

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

**What protects a large message.** The same HPKE ciphersuite, in its stateful
multi-shot mode: one context for the whole stream, one sealed chunk at a time.
The context advances a nonce on every chunk and only on a chunk that opened, so
reordering, duplication and mixing chunks between streams all fail without
anything being added. The final chunk is sealed under a different label, which
is what makes truncation a decryption failure rather than a short file.

A stream from somebody who is not in `authorized_peers` is never downloaded.
The receiver fetches the 1124-byte header and the signed manifest, sees who it
is from, and stops — the body stays on the relay until a person runs
`auu quarantine trust`. A stranger cannot make anybody pull two gigabytes, and
cannot make them spend the disk either.

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
your identity. A stranger is then refused at the handshake, before the relay
reads their request at all.

They add nothing to the confidentiality or the integrity of a message: HPKE and
the Ed25519 signature do that end to end, and would still do it if the whole
transport were plaintext. They are ML-DSA-65, so the client's authentication to
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
the bundle, and the bundle contains the suite**, so there is no such thing as
"the same sender on a weaker suite": a different suite is a different bundle,
a different fingerprint, and therefore a different person — one your
`authorized_peers` does not know. Both places where a bundle arrives from the
network check it. `auu lookup` refuses a bundle whose fingerprint is not the
one asked for, or does not begin with the short id asked for, so the relay
does not get to decide who a fingerprint belongs to; opening a message refuses
a `from` that is not the hash of the bundle beside it. An attacker who wants you to accept a signature they can
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
repair. A list from before v0.5.0, converted by the relay on upgrade,
carries no signature and is honoured as it was until you push again;
`auu inbox` reminds you until you do. That is also the one edit the relay
does not refuse: a signed row with its signature removed reads as such a
list and is honoured until its owner pushes. What catches it is the
owner's own machine, which remembers that it pushed a signed list and says
so at its next fetch — "missing or unsigned, though you pushed one" — so
the window is until then. What this does not cover is root on the relay's
host, who can replace the relay itself, which is where *What
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
the inbox at all. Nothing arrives in the background: mail moves only when a
person runs `auu inbox` or `auu wait`.

## 2. The wire, in detail

What the relay stores for one message is three fields: `v`, the format
version; `to`, the recipient's fingerprint; and `ct`, about 4 KiB of
ciphertext for a short message. Sealed inside `ct`, where the relay cannot
read a byte of it, are the Ed25519 signature, the sender's fingerprint and
public keys, the subject, thread, message id and time, the text, and any
attachments. Sign-then-encrypt, so the signature is inside the box: the relay
can see that somebody posted to Bob, and cannot see that it was you.

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
it, how many messages the mailbox holds in all (`queued`). The two normally
agree. When the list is empty and the count is not, the cursor is past mail
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
than the one it holds, naming when that was issued. Anyone the allow list
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
`state`, one of `signed`, `legacy` (converted from before signed lists,
unsigned, honoured until pushed again), `none` (never pushed; any
registered sender may post) and `broken` (no longer verifies; every
sender refused). The owner's own mailbox listing carries the same word as
`allow` on every answer, and a relay from before it omits the field.

A message posted to a channel names it in the clear: `ch` on the outer
envelope at step 3, `channel` on the request that opens a stream. The relay
reads it after the allow list has admitted the sender and before anything
is stored or charged — a sender the list refuses learns nothing about
channels — and refuses `404 no such channel "x"` for a name the directory
does not hold (`default`, for a mailbox with no directory) and `403 channel
"x" is not open: opens T` or `closed T` for one outside its period, judged
by the relay's clock with both edges inclusive. The sealed record and the
signed manifest carry the same name, so a message the relay filed elsewhere
is found out on opening. Absent means `default` everywhere, and a message
sent with no channel is byte for byte what it was before channels.

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
under the label `final`, after which nothing may follow.

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
twice. A relay whose disk fills part way through is the same case: it answers
`507`, keeps what it has, and `auu send` says the upload is kept and to resume
it when there is room.
