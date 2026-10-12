# Security model

What the relay stores, what it sees, what protects a message, and the wire in detail. Every claim here is meant to be checkable against the code. If one is not, that is a bug in the claim.

## 1. Security model

**What the relay stores.** The recipient's fingerprint, the size of each
message, when it arrived, the channel it was posted to, and its kind. That
is all. The sender's identity is inside the ciphertext, so the stored rows
do not say who wrote anything. The channel is one label per message, from
a list the owner wrote and published to every sender they admit. It is
there because the relay routes by it. The name and the period it is
checked against come out of the directory the owner signed, verified
against their registered key at the post itself and not read from the
rows the relay parsed at the push: a post to a channel that does not
exist, or is not open, is refused before the message is stored. A
directory that no longer verifies closes the mailbox — every name
refused, `default` and the owner's own post included — until they push
again. It closes rather than falling back to `default`, because falling
back would open a name an owner's own document may have removed or
closed, and because that is what a signed thing that no longer verifies
does here: a broken allow list already refuses every sender. The owner is
told at their next fetch, and `auu channel push` is the repair. The owner
chooses what the labels say.

The kind is one of three words, `envelope`, `stream` or `knock`, given by
the route the message arrived by and said beside the row in every
listing. A knock is a stranger's one message, taken past the allow list
only where the recipient's signed card says `knocks`. It says nothing
about who knocked, since that is inside the ciphertext like every sender.

Beside the rows, per mailbox, the three documents an owner signs and
pushes: the channel directory, the allow list, and the card, which says
the owner's name and two words of the owner's, `listed` and `knocks`. Each
is the bytes the owner signed and the signature, verified against the
registered key at the push and again wherever the relay acts on it. The
card's two words are parsed into columns that decide nothing. The message
itself is a file beside the database, which an operator can list, count
and delete but not read.

Every value the relay puts to that database goes as a query parameter,
never into the text of a query. That is true of a fingerprint, a channel
name, a token id and a reason alike. A test (`internal/sqlshape`) parses
the tree and fails on any query whose text is not a constant.

Since a channel keeps its mail by default, that ciphertext now stays until
its owner removes it rather than until they read it. The relay learns
nothing more from the wait. It never knows a message was read, because
nothing tells it. A fetch is a `GET` of the mailbox. The `DELETE` that
follows says only that the owner is finished with it, whether that is a
second later or a month. What it costs is room, which the per-mailbox
limits bound.

Three rows are exceptions, and each is worth stating. While a stream is being
uploaded, the relay holds a row naming the *sender* as well as the recipient.
It has to, because only the sender may append to their own upload and the
reservation must be charged to somebody. That row lives for the length of one
upload and is deleted when the stream completes or is abandoned. Nothing
in the database survives it. An upload that goes without a byte held
leaves its charge in the sender's byte budget, which is memory, and under
a `full` access log one line naming the sender, both described below.

The second is a knock. A knock row carries the fingerprint of whoever
knocked, and carries it for exactly as long as the row: until the owner's
fetch acknowledges it, until that knocker knocks again and replaces it, or
until the mailbox goes. It has to, because that is what lets a second knock
from one key replace the first, so the waiting cap counts knockers rather
than knocks and no single identity can fill a mailbox's share of it. Nothing
survives that row either: no counter, no log line and no other table keeps
it. An owner who would rather the relay held no such thing pushes a card
that says no knocks, which closes the door and stores nothing.

The third is mail this relay has taken to carry to a neighbouring relay,
which only a relay peered with another ever holds. A relay that forwards
cannot seal a bounce and should not be given the ability to, so mail that
cannot be delivered has to be somebody's for anyone to be told about it:
the row names whoever posted it. While it waits it names the recipient too.
The moment the neighbour takes the envelope both the file and the
recipient go. What is left is the poster, this relay's own name for the
neighbour, and the address: the relays the message came through and the
ones it has still to go to, by the names each relay knows them by. That
last is relay-granularity routing — not who wrote to whom, since the
recipient is gone and the sender was never there, but which relays
carried it — and it stays as long as the row does, which outlasts the
envelope.

In an ordinary hour the file and the recipient go within seconds,
because a worker hands the envelope over as soon as one arrives. What is
left goes when the window in which something could still come back about
that message has passed, which is `courier.forward_ttl` for each hop the
message had left to go, and so three days at the defaults for the last hop
and longer for a message with further to travel. When a neighbour is
unreachable the whole row waits as long as the relay keeps trying, which
`courier.forward_ttl` also sets. After that the row is failed, the poster
can read what happened to their mail for a day, and then it goes. A relay
with no `courier` block — every relay until its operator peers one — holds
none of this.

Those three rows are the whole of what the relay writes down about who is
sending something.

While an upload's row lives, the reservation counts against the recipient's quotas
and the relay's as though the stream were already queued. That holds for an
envelope posted beside it as much as for another stream. One arithmetic
answers both, so neither can be filled into the other's reservation. What
bounds one identity's uploads is the count, `max_open_uploads`, beside its
byte budget. The count is four unless the operator sets
`max_open_uploads`, across every mailbox it sends to. The open
charges the declared size. An upload with kept bytes is given back its
size less them when it goes unplaced, so there the budget charges what the
relay held. An upload that goes with no byte held gives nothing back: the
open's charge is what its reservation of the recipient's room costs.
Refunded, it would let a sender hold a mailbox full for nothing, opening,
sending nothing, aborting and opening again at once. So one identity's
reservations cost its `post_bytes_per_hour`, 256 MiB at the defaults,
however little it uploads. The count of opens is held too:
`max_upload_opens_per_hour`, 64 unless the operator sets it, refused
`429` `rate limited: upload opens` with a `Retry-After`. A stream to
several opens one upload for each recipient's copy, so 64 is four such
messages to sixteen.

An upload is fed or it goes. One nobody starts an attempt on expires ten
seconds after the open, the start window. An attempt's deadline moves only
when a whole hunk, 64 KiB, has arrived since it last moved, and then by
ten seconds, so an attempt slower than about 6.4 KiB a second, or one that
stops, is cut within ten seconds of its last whole hunk as one that
stopped short. What it left is kept or not by the threshold rule, and a
kept partial lives sixty seconds, the resume window. A deadline that every
byte moved would let a sender hold a reservation for ever on a byte every
window. An expired upload still holds the room until something meets it:
its sender's next request on it, its sender's open at the
`max_open_uploads` cap, the purge every hundredth request, or the next
post, open, knock or courier's delivery refused `507` for room, which
purges it. An attempt in flight keeps it from the purge, but only for as
long as it keeps the pace.

What remains is this. A reservation of S bytes lives about as long as S
takes at 6.4 KiB a second, the start window, the last hunk's window and
one resume window aside, and holds nothing unless it is fed. At the
defaults one identity may open a quarter of a mailbox each hour, so it can
come to hold its four open uploads, the whole of a mailbox, and keep each
for about eleven hours: 256 MiB at a hunk every ten seconds is 4,096
hunks, 40,960 seconds. That takes feeding them at about 26 KiB a second in
all, a hunk every ten seconds each, and the cost to the attacker is the
bytes, a mailbox's worth sent. It holds only on a mailbox whose owner
admits the identity, and only while the owner does: the allow list and
the upload's channel are judged again at every attempt and before the
placement, so a removal or a closed channel ends the upload at its next
attempt, with nothing given back. A reservation fed to the resume
threshold, `max_bytes`, and then dropped is kept for one resume. When it
goes it is given back its size less the kept bytes, which were held. So
it costs its sender only the threshold, and an identity may hold room for
longer each hour that way, paying `max_bytes` each time. The allow list is
the owner's answer to both, and the registration budget the operator's.
The rule costs honest senders something too. A first attempt that ends
short of the resume threshold leaves nothing, and so is charged the
declared size for the hour. So is a first attempt the relay's own disk
fails. An open the budget then cannot afford is refused `429`
`rate limited: post bytes`, with `Retry-After` saying when the budget
allows it.

**What the relay sees.** More than it stores, and this is worth being plain
about. Posting is authenticated, so at the moment a message is accepted the
relay knows which identity is writing into which mailbox. Its access log
records exactly that unless you set `access_log: "minimal"`. Rate limiting
keeps the verified fingerprint in memory for as long as a bucket lives.
Anybody holding the logs of a `full`-mode relay holds the social graph. Nothing
of that is written to the database, and no limiter key is ever written
anywhere. The one thing a stored row says about a sender is the knocker on a
knock, above, which lives as long as the knock does.
Of the lines the relay logs about faults, one names a sender, and only
under `full`: `upload abandoned unfed`, about once a minute for each
sender whose upload went with no byte held, with the declared size. Under
`minimal` that line names nobody.

The channel a message was posted to is the one thing about a message's
content the relay learns beyond its size. It is written to the row, served
in the owner's own listing, and recorded in the access log under neither
mode.

A knock is seen as any post is, and stored with one thing more: the row
says `knock` and carries the knocker's fingerprint, which is what lets a
second knock from one key replace the first. What the knocker *wrote* is
inside the ciphertext like every sender's words. What the row holds is
who they are, and only until the owner's fetch acknowledges it, it is
replaced, or the mailbox goes. An owner who would rather the relay held
no such thing pushes a card that says no knocks.

**A message to several** is several messages to the relay. Each copy is
sealed for one recipient and goes as a post, a stream or a forward of
its own, and the list of everybody it went to, the `recipients` section,
is inside each copy's seal, where the relay cannot read it. The relay
reads a count, how many the message went to, on a stream's open and on a
user's forward, which are the two requests with a body to carry one, so
that it can hold the sender to `max_recipients`. It never reads who they
are, and it neither stores nor logs the count. A courier's hand-over to
the next relay carries no count, so a relay after the first learns
nothing of it. On a plain post the relay reads nothing about the other
recipients at all. What it does see is what any post shows it: one
verified sender writing into several mailboxes close together, which a
`full` access log records as it records every post.

Every recipient
reads the whole list, by fingerprint, so there is no blind copy: a
person a message to several went to cannot be hidden from the others.
And the list is the sender's word. A reader checks that the list names
the reader, the copy's own recipient, and its form, and can check
nothing else of whom it names, so a sender can name people they never
wrote to. That is why `auu reply --all` sends only to people already on
the replier's peer list, and refuses the whole reply, naming them, when
anybody on the list is not.

A listing held open (`wait`) tells the relay nothing it did not know. It is
the owner's own listing, answered later. A directory watch (`peers`) tells
it which peers the watcher may post to, which the directory fetch the
watcher made first had already told it. It tells it nothing about a peer
who has not admitted the watcher, since such a peer is dropped before
anything is held. Neither reaches the access log. The query string is not
logged under either mode.

And there are no delivery receipts for an
ordinary message, and cannot be: its stored row has no sender, so nothing
ties it being collected to the person who posted it, and building that
would mean recording the sender on every message, which is the social
graph the relay is built not to hold. A knock is the exception and is
worth saying plainly: its row names its knocker, and the relay handles
the acknowledgement that removes it, so for knocks alone the relay could
tell that this person's knock was collected. That is the price of one
knock per knocker, it lasts as long as the row and no longer, and an
owner who does not want it takes no knocks.

**What the network says reaches a terminal escaped.** A relay is trusted
with routing and nothing else, and what it sends back is read on a
terminal. That is a display name in a listing, a machine's certificate
label, and the sentence it attaches to every refusal. Every user of every
relay reads that sentence on standard error. Each is made printable before
it is shown. A name and a label are held to a rule that leaves no control
or format character in them. A sentence has every character a terminal
would obey rather than show escaped the way Go quotes a string. That
happens where the error is made rather than where it is printed, so no
command can forget.

What a peer writes is held to the same standard twice
over. A subject, a text and an attachment name are refused at open, on
both paths, if they carry a control character, a format character, a
private-use character or a line or paragraph separator. A line break and a
tab in the text are excepted. Every print of one escapes it all the same,
as the last line under the rule and not the rule. Those prints are the
inbox listing, `read`, quarantine, watch, serve's console lines and
completion. A record in the spool is held to the rule again when it is
read back, and one that fails it is not shown. Sender names, which come
from this machine's own peer list, go through the same escaper.

`auu-admin`'s listings hold the relay's enumerated words to the set the
protocol defines, refusing the answer whole otherwise. Those words are a
registration mode, a certificate mode, an allow state, and a token's use
and state. The listings escape the relay's free text, which is a public
URL, an uptime, an access-log mode, a block's reason and a note. A pasted
token's relay and note are escaped when it is described. The key proxy's
log line escapes the path a caller sent. The same treatment covers a name
from a relay that is not this one. It covers `auu-admin`'s confirmation
before it removes a mailbox, which prints the name at the one moment an
administrator is reading carefully.

And what the relay lists is checked for shape before it is used. Every
fingerprint, serial and token id in an answer is held to its rule as it
comes off the wire. A lifetime it reports in seconds is bounded before
anything multiplies it. Every count it reports is zero or more, every
message id one or more, a parameter set one of the three, and an upload's
offset a byte count. A time that says when something happened is held to
no more than five minutes ahead of this machine's clock, since no clock
may put it ahead of now, and to the years 0000 to 9999, which this
program can write back: a message's `received`, a lookup's `created`, a
queue row's `last_try`, the status's `started`, a mailbox or block
record's `created`, and a token's `created` and `last_redeemed`. A
message's `received` is kept in the record, copied into the left-behind
file and the damaged box, and orders the damaged box. In the inbox and a
thread's latest it only breaks a tie between two messages that arrived
here at once with one relay id, since those go by this machine's clock.
Serve's opener breaks no tie by it, but it still orders the ledger
entries an earlier release wrote. A record an earlier release kept is
the exception: Load reads its `received` as its arrival, so for that
record it is the order, in the inbox, a thread's latest and serve's
ledger alike. Those releases kept any `received` a relay sent, so one
this program cannot write back gives way to the time the record's file
was last written, or this machine's clock, and auu warns once per
command until the record is next saved. The other times are printed and
written in `--json` answers. A year past 9999 breaks the first file or
answer it reaches. A time that names a moment to come is not held this
way: an expiry, a next try, a token's `not_before`, which is a moment
the token waits for, and a certificate's validity. So an answer with a
two-byte fingerprint, a negative queue or a message received next year
is refused whole as malformed, naming the field and the relay. It is not
sliced by a command that expected sixty-four characters or seeked to by
one that expected an offset. A listing page is held to the order the
relay promises as well: every row's id above the `after` the request
asked for and above the row before it. A page that repeats an id, the
one at the cursor among them, or goes back is refused whole as
malformed, naming `id`, and the fetch treats that as a transport
failure: nothing of it is acknowledged or kept. So a relay that answers
the row at the cursor again and again stops the fetch there, and cannot
have it acknowledge the row and write it under `damaged/` again on every
turn for ever. A relay that numbers a new row upward on every page passes
that check, so a fetch is bounded besides: it takes what the relay listed
up to the highest id its first page gave, leaves what is listed past it
for the next fetch, and asks one relay for at most 64 pages, 12,800 rows,
for a relay whose highest id does not hold. What it cannot open it keeps
under `damaged/`, which holds at most 64 MiB and at most 1,024 messages,
the oldest evicted first, so junk small enough to stay under the bytes is
held by the count.

Every integer that enters the program from outside has a row in
`internal/limits/ledger.txt`, and so does every slice of a string or a
byte slice. An integer from outside is a field in a JSON shape, a number
or a duration parsed from text, a length read from four bytes, or a flag.
For an integer, the row gives the range the code holds it to and the test
that takes it to the edge and one step past. For a slice, it gives the
rule that fixed the operand's length and the point it ran, with the test
that feeds the operand one byte short there, or the operand's own
arithmetic. The test beside the ledger walks the tree and fails on a site
with no row.

A record read back from the home is held to the shapes a
print slices at the point it is read. Those are a message's ids,
fingerprints and digests at `Load`, a relay's pinned hashes, a
certificate's serial, and an outbox record's id and recipient. So a file
this program could not have written is refused with the file named rather
than cut. The home's files are read strictly as well, an unknown,
repeated or differently cased key refused by name, because a key dropped
silently is a setting lost silently: a channel's `keep` misspelt in
`channel-settings.json` read as keep off, and mail answered on it was
removed from the relay.

A stream from somebody who is not in `authorized_peers` is never downloaded.
The receiver fetches the 1124-byte header and the signed manifest, sees who it
is from, and stops. The body stays on the relay until a person runs
`auu quarantine trust`. A stranger cannot make anybody pull two gigabytes.
What they can make a receiver keep is the manifest record in quarantine.
The first chunk it came in is capped at 1 MiB, so the disk they can spend
is bounded by that.

Before it asks whether a stream's sender is a peer, the receiver holds
the size the signed manifest implies to the size the relay listed. A
stream on which the two disagree is kept under `damaged/` with both
numbers and acknowledged, whoever sent it, so a stranger's that could
never be fetched whole is not quarantined for a person to trust. The one
exception is a stream that waits for a newer auu: it is recorded before
any size check, and its size is checked when a build that knows its
section fetches it from a peer, or when a person trusts it from a
stranger.

Trusting a quarantined stream fetches its manifest again and holds it to
the record before a byte of payload is asked for. A different sender,
message id or channel is refused by name: nothing is delivered and the
record is left as it was, so a relay that put another stream's file under
the row cannot make a person trust one message and receive another. The
same stream whose manifest disagrees with the size the relay listed when
it was quarantined is done with as the fetch does it: kept under
`damaged/` with both numbers, acknowledged, taken out of the quarantine,
and nobody added. That is what clears such a stream from a stranger that
a build from v0.14.0 to v0.17.0 quarantined before the size was checked
first. A record made by a build before v0.14.0 kept no size, and for it
only the size goes unchecked. What trust holds is the sender, the id, the
channel and the size, not the content: the relay alone cannot swap the
stream, but a sender working with the relay can put a second manifest it
signed under the same id, channel and size. The sender is added to the
peer list only once the message is delivered and, where its channel does
not keep it on the relay, acknowledged, so a trust refused before then
adds nobody.

**What protects a message.** Every message is sealed with HPKE (RFC 9180) in
single-shot mode, straight from the standard library's `crypto/hpke`. The
ciphersuite is MLKEM768-X25519, better known as X-Wing, with HKDF-SHA256 and
AES-256-GCM. X-Wing combines ML-KEM-768 with X25519, so an attacker must break
both. Traffic captured today stays unreadable to a future quantum computer for as long as ML-KEM-768 holds.
Each message carries a fresh encapsulation, so one compromised message does
not expose the others.

**What protects a large message.** The same HPKE ciphersuite, in its stateful
multi-shot mode. That means one context for the whole stream and one sealed
chunk at a time. The context advances a nonce on every chunk and only on a
chunk that opened. So reordering, duplication and mixing chunks between
streams all fail without anything being added. The final chunk is sealed
under a different label, which is what makes truncation a decryption
failure rather than a short file.

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
from a copy of your `~/.auu` somewhere else. The relay can revoke one
without touching your identity. A stranger presenting a certificate the
authority did not issue is refused at the handshake. One presenting none
completes it and is refused at every mailbox route and at the key lookup.
The routes open without one are the trust anchor, the health check and
enrolment, which a new machine needs before it has a certificate.
Administration is open without one too. Its authority is the file on the
relay's host and not a certificate.

They add nothing to the confidentiality or the integrity of a message. HPKE and
the Ed25519 signature do that end to end, and would still do it if the whole
transport were plaintext. They are ML-DSA, at the parameter set the
authority was created with. That parameter set is 44, 65 or 87 (`auu-ca
init --mldsa`), 65 by default. So the client's authentication to the relay
is post-quantum, as the key exchange already is. The relay's own
certificate now comes from the same private authority, so it is
post-quantum too. Every certificate in the chain is ML-DSA.

The relay holds the private key of the authority that signs them. That is the
first signing key a relay holds, and a deliberate exception to the rule that
it holds none. What a stolen copy would buy an attacker is the ability to
mint a certificate for any fingerprint. That still gets them nothing without
that identity's signing key, because every request needs both. What it would
not buy them is any message, any identity key, or any token.

**The second key, and only if the relay peers with another.** A relay that
forwards mail to a neighbouring relay does it by being a user of that
neighbour: it has an identity of its own, the courier, in a home the relay's
user owns, and posts there as any client would. That identity is the second
signing key a relay holds and the second deliberate exception to the same
rule. A relay with no `courier` block holds neither it nor a home, which is
every relay until an operator peers one. What a stolen copy of the courier's
key buys is the ability to post at that relay's neighbours as that relay,
which the neighbours' own budgets bound and which their operators end by
removing one line from their couriers file. It buys no message and nobody's
identity: the courier carries sealed envelopes and cannot open one, as the
relay it belongs to cannot. The file is protected the way the bundle is, by
the host — the relay's user alone, 0600, under the unit's hardening.
`docs/relay.md` section 1.10 says how the peering is set up.

A courier is also held to a closer clock than a user. A user's request is
fresh within five minutes of the relay's clock; a courier's, on the
forward route and the report route, within one minute of its neighbour's,
since relays keep to the minute and run NTP. The minute is judged only
after the request's signature has verified, so a stranger who names a
courier's fingerprint is answered as any stranger is and learns nothing
about the courier or its clock. A courier between one and five minutes out
is refused `503` with the code `courier-clock` and a `Retry-After` of a
minute, and waits the minute and asks again, rather than taking the
refusal for a removed line and holding its mail an hour; past five, its
request meets the `401` every request that far out meets before its
signature is read, and waits the hour. The minute is what bounds a sealed
stamp, below.

**A control message, and what a lying courier can do with one.** There is one
route on which a relay tells another relay something rather than handing it
something: an undeliverable, `POST /v1/forward/failed`, carrying an id, a code
and a sentence. A relay cannot seal a bounce and should not be able to, so
this is how a sender learns that mail could not be delivered three relays
away. The news unwinds one hop at a time along the rows each relay is
holding, until it reaches the row whose poster is the sender, who reads it in
`auu queue`.

What a hostile or lying courier can do with it is bounded by what it can name.
A report is accepted only against a row this relay really handed to *that*
courier, and once: so a courier can end the messages it was given and no
others, and what it was given is bounded by this relay's own queue caps. There
is no way to make a relay carry a report it did not earn, no way to end
somebody else's mail, and nothing to learn. A refusal says a row is not one
this relay is waiting to hear about and never which rows it holds. What a
courier can do is lie about *why*: the code is one of two words a relay can
prove about its own attempt, and the sentence is free text, so a courier can
say a message was refused when it was not, or give a reason of its own
invention. That ends mail the courier was carrying anyway, which it could
equally do by dropping it, and the sentence reaches a person with this relay's
own name for that courier in front of it and escaped. The rate is bounded by
`courier.reports_per_minute` beside the request budget. A report answered
`404`, no such message, is asked again on the ordinary backoff until the
report row's `courier.forward_ttl` runs out, since the relay behind may not
yet have written down the id it was answered with; every try is charged to
the reporting relay's own report budget and the relay asked keeps nothing for
an id it cannot match, so an invented id costs only the one inventing it.
Where a neighbour's recreated database has made two handed rows share an id,
the report is matched to the newest and answered `409` if that one has
already been told, never taken for the older one.

What a courier can also do is say nothing, and that is the limit worth stating
plainly. **A courier that swallows a report, or a relay whose report the hop
behind refuses, leaves the sender believing the message was delivered, and
nothing in the design detects it.** The reason is not a gap that could be
closed: a row a relay has handed over and heard nothing further about is the
ordinary shape of *success*, a delivered message producing no report at all, so
no relay can tell a delivery from news that never arrived. Ending such rows on a
timer would tell every sender that every delivered message had failed.
`courier.forward_ttl` ends a row that is still *waiting*, which is a relay that
never got the message away, and that is a different thing. So the guarantee this
route offers is one-sided: news that arrives is news a relay was really handed
and can be trusted about which hop failed, while news that does not arrive
proves nothing either way. A sender who needs to know a message was read needs
the recipient to say so, which is a message and not a relay's business.
`docs/relay.md` says what keeps the silent case rare and what an operator sees
when it happens.

One case that used to be silent is not. A relay whose answer to a hand-over is
lost cannot match the report that comes back for it, and so refuses it; but its
row is still waiting, so it tries again, and the neighbour's `409` now carries
how that row ended, which is how the news gets through. After the neighbour has
purged its ended row, a day later, a retry meets the bare refusal instead and
reads `refused: …: already carried`, which is true about the outcome and silent
about its cause. The sender's own relay had every retry before then, at least
one an hour, to learn the code.

That answer rests on the relay's memory of what it has carried: a hash of
the recipient and the ciphertext of every envelope it forwards or
delivers, kept as long as the envelope could still be alive ahead of it. A
hash that stands is never evicted, so `courier.carried_max_rows` is a
ceiling the relay refuses new mail at; one whose window has passed is not
counted, and is purged before the relay refuses. A hash outlives the row
that wrote it, so the queue's shares do not bound it, and one person or
one neighbour could otherwise fill the ceiling alone and stop every
forward and every delivery from a neighbour for days. So a hash is charged
to whoever posted it, by the fingerprint the signature proved, against
`courier.carried_rows_per_poster` for a person and
`courier.carried_rows_per_courier` for a neighbour. It costs one for each
`courier.forward_ttl` it is kept, and over the share the answer is `429`.
One poster's standing hashes stay at or under its share at every moment,
across any window and any mix of paths. `docs/relay.md` section 1.10 gives
the numbers.

What remains is this. The shares are kept in memory and the hashes on
disk, so a restart refills every share while the hashes stay. A
poster's bucket is forgotten when it is the least recently seen of
100,000 and another poster arrives, and it comes back full. Both let one
poster past their share, and neither lets anybody past
`courier.carried_max_rows`.

One boundary of the couriers route rests on a setting, and it is the same setting
the rest of this document's disclosures rest on. The route answers a relay's
registered identities, which is how it avoids being the oracle a silent courier
mailbox exists to close — but under `registration: "open"`, the default, a
registered identity is anybody who asked. So on an open relay the accept-side
peering joins the set that relay has already chosen to show anybody: the cards of
users who asked to be listed, and the answers to key lookups.

What is disclosed is which relays carry mail *in*, by fingerprint rather than by
the operator's local name, and never which relays it carries *to*. An open relay
cannot forward outward at all, since `courier.home` beside open registration
refuses to start. Nothing about a message is disclosed and no name a sender needs
is withheld. The remedy is `token` or `closed`, which is the remedy for the rest
of it. Withholding the list from a relay's own users is not one, since a
recipient who cannot read it cannot admit a courier and cannot be reached from
off their relay. `docs/relay.md` section 1.9 says this where an operator chooses
the setting.

A report is never made for a report: a report the next hop back will not take
is a line in this relay's log and nothing further, so a chain ends rather than
echoing. And a report is never a message — no seal, no mailbox, no file, no
hash — so what one costs a relay is a row's state and one small request.

Three lines in the relay's log are about undeliverables it could not pass
back: one for a neighbour it accepts from but cannot dial, which is the one-way
peering the relay already names at its start, met at the moment it costs
something; one for a report its own queue had no room to write down; and one for
a report the neighbour behind refused. Each is rate-limited to one a minute on
its own key, and each names the neighbour by the name this relay's operator gave
it and never an identity, which is what every courier line here does.

The relay also learns how many machines an identity uses and what each one
calls itself. That is operational data it needs in order to revoke one of them.
It is not who talks to whom, and `access_log: "minimal"` is unaffected.

**Which algorithms, and what stops them being downgraded.** An identity is
built from a *suite*. Today the only one is Ed25519 for signing and
MLKEM768-X25519 for receiving. `auu id` names it, and `auu peers ls` marks
any peer who is not on it.

There is no negotiation, and that is the point. **A fingerprint is a hash over
the bundle, and the bundle says which suite it is.** The original suite says
so by its length alone, since its bundle predates there being a suite byte.
Any other says so by a leading byte that makes it a different length again.
So there is no such thing as "the same sender on a weaker suite". A
different suite is a different bundle, a different fingerprint, and
therefore a different person, one your `authorized_peers` does not know.
Every place a bundle arrives from the network checks it. `auu lookup`
refuses a bundle whose fingerprint is not the one asked for, or does not
begin with the short id asked for. So the relay does not get to decide who
a fingerprint belongs to. Opening a message refuses a `from` that is not
the hash of the bundle beside it, and opening a stream's manifest does the
same. An attacker who wants you to accept a signature they can forge has to
persuade you to add a new peer, out of band, by hand.

Nothing negotiates at the transport either. Every TLS connection this project
makes to a relay, or takes as one, is pinned to TLS 1.3 with `X25519MLKEM768` as the only key
exchange, and refuses less. That covers a client's requests, the anchor
fetch that comes before a new user has anything to verify with, and the
relay's own listener on both its branches. There is no option to relax it,
since every relay is built from this tree and there is nothing older to
meet. So a recording of who talked to whom made today is protected by the
same hybrid as the messages inside it. A relay that will not make that
handshake is named by the client in one sentence rather than by Go's alert.
That is one behind a TLS terminator that lacks the hybrid, or something
that is not this relay. A relay run with `tls.mode: "off"` behind somebody
else's terminator is that terminator's TLS, not the relay's, and this says
nothing about it. The key proxy's connection to Anthropic's
API is Anthropic's TLS and outside this.

**What an administrator sees.** The list of mailboxes, with fingerprints,
display names, how much each is holding, and how many channels each has
defined. That is the count, never the names, which are the owner's to
publish to their senders. Beside it, the state of each of the three
documents that owner signed — the allow list, the card and the channel
directory. Every state is reached by verifying that stored document
against the registered key at the moment the record is read, never by
reading a column the push wrote. A mailbox that has never pushed one
of them has no state to show for it. What is printed of each differs, since
each says something different when it is there: a count and `signed` for
the allow list, what the card says of itself for the card, and the bare
word for the directory. `broken` is the word to look for in any of the
three, and it is what an administrator is there for: it means the row was
changed by something that was not the owner's push, and the relay is
refusing on the owner's behalf until they push again. Never a message.
An administrator has exactly the same view of the ciphertext as the relay
does, which is none. That list is inherent in running a relay, which is
why the file naming administrators belongs to whoever runs the host and
to nobody else.

**Enrolment tokens.** Signed by the issuing administrator's own identity
key, so the relay holds no new private key material. Removing an
administrator from the authorized file invalidates every token they
issued. A token must also be registered with the relay before it can be
redeemed, which is what makes revocation and single use real rather than
hoped for. Tokens are bearer credentials. Send them over TLS. The relay's
audit log records a token's id and never the token. The relay does not
record which token created which mailbox. That link appears once in the
operator's audit log and nowhere in the database, because a permanent
table of who invited whom is a social graph of a different kind.

**The allow list.** Owner-signed, like the channel directory. `auu allow
push` signs the list of who may post to you with your identity key. The
relay verifies the signature against your registered key before storing
it and again on every post, and on a stream at its open, at each of its
attempts and before its placement, with no cache. A row edited in the
relay's database therefore refuses every sender but the owner rather
than admitting one. A sender is told what a refused sender is always told.
Your own listing says `broken`, `auu inbox` says so, and your next
`auu allow push` is the whole repair, whatever issue time an editor left
on the row, since the newer-issued rule holds only between two lists you
signed. A row with no signature is broken too. A signed row with its
signature removed refuses every sender but the owner at once. There is no
state in which the relay honours a list it cannot verify. So a restricted
mailbox whose list does not verify is closed until its owner pushes, and `auu
inbox` tells them so on every fetch. Your own machine also remembers
that it pushed a signed list, and says so if the relay's row has gone
altogether. What this does not cover is root on the relay's host, who can
replace the relay itself. That is where *What is not protected* below
draws the line. The signature moves the bar from editing one table to
replacing the binary.

A removal takes effect for an upload already open, not at the sender's
next open alone. Before a byte of each attempt is read the relay asks the
list again, and asks it once more after the last byte and before the
stream is placed, under the upload's lock. A sender you removed is
refused at its next attempt with the sentence a refused post gets, and an
attempt running when you removed it places nothing and is refused the
same way. Either way the upload goes whole, its reservation released and
the bytes the sender sent before the removal deleted with it, and the
open's charge stands, as a refused post's does. Without this a sender
removed an hour into a large stream, which at the pace runs for hours,
would land it all the same. A channel closed under an upload is judged
at the same two points and ends it the same way.

**The card.** Owner-signed, the third document. `auu card push` signs
your name and two words, `listed` and `knocks`, with your identity key,
and the relay verifies the pair against your registered key before storing
it. A row edited in the relay's database stops verifying. A card that
does not verify says nothing on your behalf: the relay reads it as
`broken`, your own listing says so, `auu inbox` says so, and a bare `auu
card push` is the whole repair, whatever issue time an editor left on the
row, since the newer-issued rule holds only between two cards you signed.
A mailbox with no card has said neither word, and so has one whose card
says neither, which is what `auu card clear` pushes. The name on the card
is a name from the wire wherever another person reads it: a suggestion at
a prompt, and a local label only once they accept it. `knocks` is the
word the relay enforces: a knock to a mailbox is let past the allow list
only when the card, read and verified at that moment and never from the
column the relay parsed at the push, says it, and a card that does not
verify takes none, said in the relay's log once a minute naming the
mailbox alone. The relay says one sentence for no card, a card that says
no and a card that does not verify, since the state of somebody else's
card is not a stranger's to learn.

**Where trust comes from.** `authorized_peers`, and nowhere else. The relay's
key lookup endpoint is a convenience for typing accuracy. It is not a trust
anchor, and `auu lookup` deliberately refuses to add anyone. Confirm
fingerprints with people directly.

The card listing is a second way a
person may choose to fill the file, and it rests on exactly one thing:
who the relay admits. The relay can prove, and the client checks, that a
listed bundle hashes to its fingerprint and that its card was signed by
the key inside it. That is a statement about bytes, and the client
verifies every entry itself, dropping what fails, so an edit to the
relay's database removes a name and never adds one. What the relay
cannot prove is that a fingerprint belongs to a person. On a relay that
invites by token, a listed identity was let in by an administrator who
signed the token, and its name is its own claim. On one that registers
anyone, an identity proves nothing about who holds it. So a peer taken
from the listing is trusted as far as the relay's admission is, and no
further, and `auu peers fetch`, the one
command that adds from it, prints which kind of relay it is before it
asks, at a terminal, and never without a person. The name on a card is
the owner's claim, offered at the prompt as the local name and never
taken as one until the person accepts it. A relay that lies about its
mode is admitting anybody, which is the case the sentence warns of.

A vouch is the third way, and it rests on a peer already in the file: a
message from somebody you hold carrying their signed word that they hold
another key, under a name. It counts only when its signer is on your list
and it verifies under the key you hold for them, never the bundle the
message brought. From anybody else it is held in quarantine and adds
nobody. There are no chains and no arithmetic: a vouch from somebody you
added on a vouch is a vouch from them, judged the same way. `auu peers add
--vouched` is the one command that adds from one, at a terminal, saying
whose word it is, with the voucher's name offered at the prompt and never
taken until the person accepts it. It writes a comment above the entry
saying whose word it was. A peer who is compromised can introduce anybody
to you, which is what trusting them means, and no more than they could
do across a table.

**A courier is admitted to a mailbox and never to the peer list.** Forwarded
mail brings a second kind of sender, and it is the one kind that is not a
person. A relay cannot open an envelope, so when mail arrives from a neighbour
the only sender the receiving relay can prove is that neighbour's identity, its
courier, and that is what the recipient's allow list is asked about. So a
recipient with a restricted list admits a *relay* rather than a person, and
admits everybody who can post through it along with it.

That is why it goes nowhere near `authorized_peers`. A peer is somebody whose
key seals mail to you and whose fingerprint you confirmed with them. A courier
is admitted so that a delivery may be accepted at all, and it can read nothing.
A relay cannot open an envelope, and admitting one does not change that.

What it can do is worth stating exactly, because the narrower reading is the
tempting one. An allow list is one list and the relay asks it one question: may
this fingerprint put something in this mailbox. There is no separate answer for
the forward route, so **whoever holds a courier's key may also seal a message
and post it directly**, as an ordinary sender would. Two things bound that.
Whoever holds the key is whoever the relay's operator put in their couriers
file, which the confirmation says in as many words when it names the relay's
registration mode. And such a message lands in quarantine, not the inbox: what
decides that is this identity's peer list, and admitting a courier does not add
anything to it, so a courier's own message arrives as a stranger's does and is
read only if its recipient trusts it. The courier's advantage over any other
registered identity is that a restricted mailbox refuses a stranger outright and
does not refuse it. Putting one on the peer list would make it addressable as a
correspondent and would put a relay's identity where a person's belongs, and
`auu allow push` would then send it as a peer with no record that it was
anything else. It is kept in `relays/<name>/couriers` instead, per relay
because a courier's fingerprint means nothing at another, and merged into the
signed list only at the push.

What a person is told before they admit one says what it admits, in those
words, and `auu allow add --courier` asks at a terminal or takes `--yes`, so
it is not a command the skills run. The fingerprint comes from the recipient's
own relay rather than from the courier or from anything the sender typed:
`GET /v1/couriers` answers that relay's own users with the neighbours it accepts
from, which is what they need in order to be reachable and what their operator
could not withhold and still forward their mail.

A knock is the one message that crosses without an entry, and it adds
none. `auu knock` reaches somebody whose card says they take knocks, and
what it buys the knocker is a sealed line in the other person's
quarantine, where every stranger's message goes. One: `auu knock` sends
one and then refuses, since the person is a peer by then. The relay does
not count them — it has no memory of who knocked — so what bounds a
knocker who is not running this client is the operator's two settings,
`max_knocks_waiting` on the mailbox and `knocks_per_hour` on the sender.
Nothing on the knocked side is trusted by its arrival: the name the knock
carries is the sender's own claim, shown as theirs, offered at the prompt
when somebody runs `auu quarantine trust` and never taken as a label until
a person accepts it. On the knocking side the peer being added is that
person's own decision, asked for at a terminal before anything is sent,
which is why neither `knock` nor `peers fetch` is a command the skills
run.

A knock may carry up to four vouches the knocker keeps, each a peer's
signed word that they hold the knocker, chosen by the knocker, since what
it carries tells the knocked person who vouches for them. What one adds is
a sentence and no more: a vouch counts only when its voucher is somebody
the knocked person already holds, it verifies under the key they hold for
that voucher, and it is for the knocker's own key, so a vouch about
somebody else cannot be presented as one's own. The quarantine line names
those vouchers and counts the rest, and `auu quarantine trust` says whose
word each is before the name is asked. It adds nobody, opens nothing past
the relay, and changes nothing about who decides. The relay sees a larger
knock: `knock_max_bytes` is 20 KiB by default, which takes four at their
longest, and the health answer carries it so a client refuses a knock
with vouches over it before sending, naming how many to leave off; one
with none meets the relay's own refusal, which names the setting.

The one identity trusted without an entry is your own. A message you sent
yourself is opened, verified and delivered like any other, and the relay
accepts it for your mailbox whatever your allow list says. Sender
and recipient are the same authenticated identity, which a `full` access log
records as such.

**What is not protected.** The relay knows who talks to whom, as above. It can
drop messages or refuse service. It cannot read, forge, or redirect them. An
attacker with root on the relay's host is outside this model altogether.
They can do anything the relay can, including replacing it, and the relay
cannot defend itself from the machine it runs on. What such an attacker still
cannot do is read or forge a message. *Keeping a relay private* in
`relay.md` says what keeping the host secure means.

Compromise of your `identity.json` gives an attacker everything. That is
your mail, and the ability to write as you. With a passphrase set (see
*Encrypting your keys*) the file holds only your public half. The keys are
ciphertext under a passphrase stored nowhere, and a copy of the home yields
them only to somebody who also has the passphrase. What a copy still
yields, passphrase or not, is the mail in `inbox/` and `sent/`, which is
stored open.

**The receiving agent.** A signature says who wrote a message. It says nothing
about whether the contents are safe. Inbound text and attachments are treated
as data by the skill, never as instructions. Unknown senders never reach
the inbox at all. Nothing arrives unasked. Mail moves only when a command
fetches it. Those commands are `auu inbox`, `auu wait`, `auu watch --fetch`,
and each round of `auu serve`.

**What an induced action can do.** The cryptography authenticates whatever
the key signs. So the attack that matters against an AI is not breaking a
message but talking the AI into originating one. While the key agent is
unlocked, any process running as the user can have it sign, and a message
built to subvert an AI could have it send as the person. No confirmation
the agent asked for in-band would help, since the same process answers it.
So an unlock has a scope. The agent decides by the domain string at the
front of what it is asked to sign, never by who asks. Every construction
here has one, and a relay request is decided by its method and path
against the relay's route table. A plain `auu unlock` is receive scope.
The agent opens mail, signs the transport, and signs what lists, fetches,
watches and acknowledges. It refuses to sign a message, a stream's
manifest, a channel directory, an allow list, a card, a vouch, a token, or
any request that posts, uploads, registers, pushes or administers, a knock
among them: a knock is a message and its route originates, so an agent
unlocked to receive refuses it twice over, exit 4 with nothing sent.
Anything it does not recognise is refused too. `auu unlock --send` is
everything, and then back to receive. It asks the passphrase again, and
its window is ten minutes by default. An induced action in receive scope
can therefore fetch mail and acknowledge it, which is to say delete it
from the relay. It can renew this machine's own certificate, and nothing
more. The relay issues that certificate to the signing identity's
fingerprint and to no other, on the live certificate it then retires, with
no token and for no other machine, so it is maintenance and not an act. In
a send window it can originate as the person, which is why the window is
short and typed for.

This does not reach a home that was never encrypted, whose keys are files
any process can read. Nor does it reach one whose passphrase is in a file,
which the AI can read too. The one accepted exception is `auu serve`. An
expert originates unattended by design, to the channel it serves, and is
unlocked with `--send --ttl 0` on a machine that is nobody's desktop. Serve
refuses to start under receive scope and says so.

**The agent's directory.** The key agent's socket, lock and log live in a
runtime directory: `$XDG_RUNTIME_DIR/auu`, or with none,
`%LOCALAPPDATA%\auu` on Windows and `auu` under the temporary directory
elsewhere, which on Linux is `/tmp/auu`, where every user of the machine
can make a name. That directory must be this user's own directory and
never a symbolic link. What stands at the path is looked at without
following a link before anything is made there, and a symbolic link is
refused by name, a dangling one included; a Windows junction, which Go
reports as an irregular directory, is not, and needs none, since
`%LOCALAPPDATA%` is the user's own. A link another user planted at `/tmp/auu`
pointing at a directory this user owns would pass an owner check that
followed it, and the agent would write its socket, lock and log there and
make that directory 0700; on Linux that needs only `fs.protected_symlinks`
off. Off Windows the directory is then opened without following a link,
and its owner and mode are judged, and a loose mode made 0700, through
that handle, so what is checked is what is changed and a link put at the
path after the look is refused by the open. A directory another user owns
is refused too. Each of these refusals names the path and says to set
`XDG_RUNTIME_DIR` to a directory of the user's own, since every command
that reaches the agent makes the same check.

## 2. The wire, in detail

What the relay stores for one message is three fields, and a fourth on a
named channel. `v` is the format version. `to` is the recipient's
fingerprint. `ct` is about 4 KiB of ciphertext for a short message. `ch` is
the channel, omitted for the default one. Those four fields are all a relay
reads, and all there will ever be: a relay refuses a fifth, takes any
version from 1, and stores and passes on the bytes it was given, since what
a version means is between the sender and the recipient, and a relay on the
path that refused one it did not know would bounce mail for a matter that
is not its own. Sealed inside `ct`, where the
relay cannot read a byte of it, are the Ed25519 signature, the sender's
fingerprint and public keys, the subject, thread, message id and time, the
text, and any attachments. Sign-then-encrypt, so the signature is inside
the box. The relay sees that you posted to Bob, and stores no sender —
except on a knock, whose row names its knocker for as long as the row
lives, which is the one exception above.

**The version, outside and in.** A message is version 1, or version 2 when it
carries a section its sender marked critical: a part a reader that does not
understand it must not read past. A reader from before sections refuses any
version but 1 before it decrypts anything, so it never reads such a message
with that part silently dropped. That is a word to older readers and not a
protection against a relay: the outer `v` is signed by nobody, and a relay
can rewrite it. What holds for this build's readers is inside the seal. The
sealed record carries its own version under the signature, the outer one
must equal it, and a version 1 record with a critical section, or a version
2 record without one, is malformed. So what a relay buys by rewriting the
outer `v` is a message the recipient refuses, which it could already buy by
garbling the ciphertext. A record from a build before the sealed version
carries none, and is refused as malformed in those words.

The message id, the thread and, on a reply, `in_reply_to` each have a
message id's shape. That is 32 lowercase hex characters. `in_reply_to` is
the id of the message being answered. A new thread is given an id of its
own, not its first message's. That is a rule of the format, not a
convention. A record whose id, thread or `in_reply_to` has any other
shape is refused when it is opened, kept under `damaged/` as malformed and
acknowledged. `auu send --thread` refuses one before anything is sealed. A
stream's manifest is held to the same rule.

**Nothing the network names is a path until its rule has run.** Eight
things that arrive over the wire become part of a path somewhere. Each
has one rule and a named place it runs, before the value goes near a
filesystem or a database. A signature proves who wrote a value, not that
the value is safe. In order, they are as follows. A *fingerprint* in a URL
names a mailbox's directory on the relay, and the relay checks it is 64
lowercase hex before it reads the signature. An *upload id* names an
upload's file, checked as 32 lowercase hex before the row is read. A
*token id* is checked the same way before the store is asked. An
*attachment name* becomes a file on the receiver, and the receiver never
depends on the sender for it. Whatever arrives is held only to what any
text is held to (UTF-8, one line, no NUL, a size) and written under
`message.SafeName` of it. `SafeName` takes the base name on either
separator, makes every forbidden or Windows-forbidden character `_`, trims
trailing dots and spaces, makes a leading dot `_`, prefixes a Windows
device stem, cuts to 200 bytes, and gives `attachment` when nothing is
left. The name is made unique at the write by an exclusive create and a
numbered suffix, so that what the filesystem folds is settled by the
filesystem. The sender is held to the rule that its name is already that
form (`SafeName`'s fixed point, `ValidAttachmentName`), at `envelope.Seal`
and `stream.BuildManifest`. So an honest sender is told before anything
leaves and a dishonest one changes nothing. A *channel name* becomes a
directory under an expert host's serve directory. It is held to the
directory format's rule at the relay for every post, at every push of a
directory, and at the client's `--channel`. That rule is no separator of
either kind, no colon, and no Windows device stem. A *relay host* names
the authority's record of the relay, and `auu-ca` holds it to the shape of
a DNS name or an address before any record is filed. A *message id* names
the record's file, and is a message id at open, in a manifest and at the
store. A *thread id* names a directory and a worktree under an expert
host's serve directory. It is held to a message id's shape at open, in a
manifest, and checked again by `auu serve` before it is joined onto
anything. One test walks every one of them with `..`, `../x`,
`x/../../y`, `a/b`, an absolute path, a backslash form, a drive
letter, a drive-relative name, a Windows device name with and
without an extension, a NUL, the empty
string, `.` and a 300-byte name. A new place that turns something from
the network into a path gets its row there first. Behind that table is a
ledger, `internal/fileopens/ledger.txt`, with one row for every call in
the tree that opens, makes, removes, renames, lists or runs something by
a path. Each row says whether the path is the program's own, the
operator's, derived from something the program read back, or from the
network with the rule and the point that check it. An operator's path is
a whole path used as given, a value from a configuration file with the
directory it resolves against, or a name joined under a directory with
its rule. A path derived from something read back is an entry of a
directory the program owns, held to the reader's rule. Every row that is
not the program's own names the test that drives that set through its
rule, or says why nothing is joined. Its test parses the tree and fails
on a call with no row, so a ninth component would be found before it was
a finding. A path in a configuration file that is not absolute is
relative to the file's directory, never to the directory the program was
started from. So the same file means the same thing under systemd and
from a shell. And a name list is one guard, never complete on its own.
Every file the program reads or creates by a name from the network, or
from a directory entry it read back, is opened through `internal/regular`.
That asks the open handle what it is and refuses a device, a named pipe,
a socket, a directory or a symbolic link under any name before a byte
moves. A create is exclusive, so nothing that already stood under the name
is opened, and no such name is a rename's destination. On Windows the
device rule asks the OS itself. The Windows CI job holds the hand list,
which is the rule everywhere else, to be no narrower than what its OS
says. Windows versions differ in which names are devices under a
directory (Server 2025 resolves `NUL` alone). So the list is the union
across them, and the handle check is the safety net for a name it does
not hold.

Any peer may name any thread id. So serve answers a thread only for the
peer who opened it. A message on it from anybody else gets no directory and
no worktree. It is left unanswered in the inbox. The opener is decided by
arrival on this machine, by its own clock when the message was first kept,
and the ledger records that. So a relay with its clock ahead cannot put its
message first, but the relays' order of delivery, and when each fetch runs,
still decide who opens a new thread. So can a large message to several,
which goes as one stream to each recipient: a co-recipient has the thread
id while the expert's copy is still uploading, and a small ask from them on
it can arrive first and open the thread. A thread that has been answered or
tried is not moved by any later arrival. A ledger entry an earlier release
wrote keeps the relay's stamp under the same key and is not rewritten, so a
thread opened before the upgrade is ordered by that stamp until something
on it is tried. A thread carried over from a v0.17.0 ledger, which kept no
senders, takes its opener from what this home wrote: an answered message's
asker is the recipient of the copy of the reply serve sent, which serve
addressed to the message's verified sender alone, so nothing a peer posts
can name it. A message with no reply, or one whose reply's copy is gone,
takes its opener from the earliest of its messages still in the inbox. A
message id and a thread id are the sender's to choose, so a co-recipient
who saw an id could post a note under it once the owner removed the
original. A record is therefore taken as a carried-over entry's message
only when it is on the entry's thread and, on a thread tried or answered,
the earlier release fetched it: such a record has no arrival of its own and
is lent the relay's received (or, when that cannot be written back or is
more than five minutes ahead of this machine's clock, its file's time or
now, and is then never taken), which must be no later than the
thread's last attempt and the five minutes the relay's clock is held to. A
record this release fetched came after the upgrade, after every attempt the
earlier release made, and is never taken there. For mail fetched before the
upgrade the bound is the relay's word, so a note posted under a removed
message's id and fetched by the earlier release, with a received the relay
put inside the bound, would be taken; an answered message never reaches
that rule while its reply's copy stands. On a thread with anything tried
before the upgrade only those messages open it, in the order serve dealt
with them, and a message the earlier release left pending, or one this
release fetched, opens nothing while one stands. An answered thread loses
its opener only when both the asker's message and the copy of the reply are
gone: the owner's own removal, or a copy never kept because its local save
failed after the send, which the send said. Where the messages tried before
the upgrade are from more than one peer, the earlier release's record may
not say who came first: it kept only an attempt's last time, so a message
whose attempt failed may have moved, and an answer kept to the second ties
with another in the same second. Such a thread is nobody's, and each peer
opens a new thread. A message the earlier release passed over that truly
came first, a stream it held for a newer build while a later message on the
thread was answered, does not open the thread: the answered one's sender
does. A thread whose opener's messages the owner has removed may take
another sender's. One with none of its messages left has no opener, and
once anything on it was tried or answered it is nobody's: serve answers no
message on it from anyone, the original asker included, and leaves each in
the inbox, unanswered and uncounted. Were the first message after the
upgrade to name its opener, any peer who knew the thread id could take the
thread over.

**The HTTP layer has bounds of its own**, and they are not settings. The
relay speaks HTTP/1.1 alone. HTTP/2 is off on the listener and not offered
by ALPN, so a client offering `h2` is answered over HTTP/1.1. Every
property below holds under the one protocol the relay's tests run rather
than a second one with its own stream, reset and header semantics. Those
properties are the refusal before the body, the drain, `Connection: close`
behind a refusal, and the stall deadline on the connection. The request
line and headers together are capped at 32 KiB, answered `431` by the
standard library before the relay sees the request. The largest header the
protocol carries, the request signature, is Ed25519 and about 200 bytes.
The relay refuses an auth header longer than its five fields can be before
it cuts a field from it. Every body is read under the cap of its route. A
post is read at `max_bytes`, never above 64 MiB, plus 64 KiB of framing,
and so are every forward, delivered here or carried on, and a courier's
delivery; the envelope each carries is then held to `max_bytes`, never
above 64 MiB, and refused `413` with `envelope too large` over it, a
forward with a path still to go before anything of it is charged to
the carried share, queued or written. An allow
list or a channel directory is read at 1 MiB, the envelope those documents
travel in. Every other request is read at 64 KiB, a card among them, since
one at its maximum is a few hundred bytes. A body that declares itself
over the cap is refused `413` before a byte of it is read, the sentence
naming the cap.

The signed documents have caps of their own, which are not the bodies':
512 KiB for a channel directory, 128 KiB for an allow list, 512 bytes for
a card. Each is the document at every maximum as a client marshals it
compact — 425,934, 67,141 and 199 bytes, measured — with room above for a
signer whose encoder indents, since the bytes are whatever that encoder
produced and the signature covers them. Each is checked **before the
signature**, at the push, at every reading of a stored document, and by
the client before it sends one: a length is the one check that costs
nothing and tells the caller nothing, and without it a registered identity
could pad a document with whitespace to the route's cap and have every
reader verify the padding — the relay on every post to that mailbox, an
administrator's listing on every mailbox in a page. A push over the cap is
refused `400` naming the bytes, the cap and to send it compact, and
nothing is stored. A stored document over it reads as broken, which fails
closed as any document that does not verify does: an allow list refuses
every sender, and a directory closes the mailbox to every post, `default`
included, until the owner pushes again. No document `auu` signs can be
over a cap and no push can store one, so a stored document that is over
one was put there by something that is not a push — an edit on the host,
or an older relay that held a document another tool signed before these
caps existed. The owner is told at their next fetch, and their push is
the whole repair: the relay holds a push to the time inside the verified
document, so a row that does not verify is no bar to replacing it.

The stream `PUT` is bounded by the size its open declared. On every
authenticated route the order is the certificate, the auth header parsed,
the identity it names looked up, then the body, then the signature, the
stream PUT excepted, whose signature is over an empty body and comes
before it, and the admin routes excepted, which read the body before the
administrator is looked up. Everything that can be judged without the body
is judged before it, so a stranger's sixteen megabytes are refused unread.
The signature comes after the body because it is over the body. Every
refusal before the body closes the connection behind its answer, the
`413`, the admin routes' `411`, the `401`, the in-flight `503` and a `429`
once the address's budget is spent alike. The standard library would
otherwise read up to 256 KiB of the body the handler declined before
writing the answer on a connection it meant to keep, and wait for a body
that never came. That is what a refusal that leaves the body unread must
not do.

A caller who has not proved who they are learns nothing about the
fingerprint it names that costs less than a refused signature. Every
refusal before the signature that turns on the fingerprint named is
charged to the source address's unauthenticated budget,
`unauthenticated_per_minute`, and answered `429` once that is spent: the
`401`, and a body refused before its signature is checked, for its
declared length, for a read over the route's cap or for a read that
failed. The `401` is charged on every authenticated route, `/v1/uploads`,
`/v1/listed` and `/v1/couriers` among them; the body refusals are charged
on every route under `/v1/mailbox/`, on `/v1/forward` and
`/v1/forward/failed`, and on the admin routes, the routes that read a body
before its signature. A refusal that does not turn on the fingerprint,
such as a `400` for a malformed fingerprint in the path, a storage `500`
or the in-flight `503`, is not charged. On a route under `/v1/mailbox/`
the identity is looked up before the body, so a registered fingerprint is
told `413` where an unknown one is told `401`, at the same price; that
says whether a mailbox exists, which a key lookup says on the same budget.
The admin routes read the body before the administrator is looked up. A
body that declares no length, a chunked one, is refused `411` `a request
to an admin route declares its body's length`, one declared over the cap
`413`, and the rest is read whole, at most 64 KiB. So every byte is
bounded and read alike before the administrator is known, and every
refusal before the signature, the `400` for a read that failed among them,
is charged and the same for every fingerprint. The `403` `this relay has
no administrators` is charged as well. One difference remains past the
read and the lookup: an administrator's fingerprint costs the relay a
signature verification, Ed25519 and tens of microseconds, that anyone
else's does not, so a patient caller from many addresses could in
principle tell them apart by timing, each probe still at a refused
signature's price. `auu-admin` always declares a length, so nothing of
ours meets the `411`. A relay before this release answered the `413` free
and only once the fingerprint was found, which told a registered
fingerprint, or an administrator's, from a stranger's at no cost when the
fingerprint was known.

The client holds the same bounds from its side. Its transports offer
http/1.1 alone by ALPN and never attempt h2. A response's headers are
capped at the same 32 KiB, and a relay whose answer runs past it is
refused as a malformed answer. A JSON answer is read under twice the
default `max_bytes`. A listing page, the one answer that grows with the
relay's setting, is read under twice the relay's own `max_bytes` plus
64 KiB, and never more than 128 MiB and 64 KiB whatever the relay says. So
the memory a relay can make a client spend on a page, on an `auu serve` or
`auu watch` host that lists for days among them, is bounded by the client
and not by the relay: a relay that says a gigabyte on its health answer
cannot have a page of two read whole. The relay says its `max_bytes` in
its health answer, and the client learns it once. It asks for that figure
again only when a page is refused for its size, in case the setting was
raised under a client that runs for days. A relay of this release stores
no inline row over 64 MiB, whatever its `max_bytes`, and ends a page at
its `max_bytes` and never past 64 MiB, so the envelopes of a page it
builds never pass half the client's hold but a lone first row's. A relay
not yet upgraded fills a page to its whole `max_bytes`; a page of it over
a hold already at the ceiling is asked for again with half as many rows,
down to one. A lone row over the hold, stored before the relay's upgrade,
on a relay not yet upgraded, or under a larger `max_bytes` than the relay
says now, is the one size failure left: every fetch of that mailbox stops
at it, as a transport failure on that relay alone, until the row goes or
the cursor is moved past it. The operator's `auu-admin mailboxes purge
FP`, which discards all the mailbox's queued mail, is the recovery that
ends it. The owner can step past the row with `auu cursor reset --relay
NAME --to ID`, losing that row alone and letting the mail after it
through, but the row stays counted on the relay, so until the operator
removes it every fetch from that relay ends at exit 5 with the cursor said
to skip mail, a multi-relay `auu inbox` stops there without fetching the
relays after it, and `auu watch` stops watching that relay, and ends when
it is the only one. A relay that does not say its `max_bytes` is refused
by name. A stream route's answer, the placed stream's id or an error's
sentence, is read under 64 KiB. The trust anchor answer is read under
1 MiB. Each is refused by name over it, the same rule and not a cut that
fails later as JSON. A directory or an allow list is held to the 1 MiB cap
before a byte is sent. The stream routes run on a client with no
whole-exchange timeout and a stall rule of sixty seconds, the relay's
resume window, on both bodies. A two-minute whole-exchange timeout, under
the one-request wire, meant a stream needing more than about four minutes
on the link could never be placed. An upload the relay stops taking, and a
download the relay stops sending, are cut with a sentence naming the
stall. The next attempt or the next range picks up from where the relay's
copy ends.

Within the hold, an answer that declares its length, as every answer of a
relay of this release does, is read into a buffer of that length, its keys
are checked in place, and it is decoded once: the read costs the page's
own size, and what the page carries is copied out of it once into the
values it decodes to, so a page of envelopes is held at about twice its
size while it is taken. A relay that withholds the length has its page
read as it comes, the buffer grown as the bytes arrive, at up to about
four times a page in allocation and two and a quarter at once, bounded by
the hold, the one cost a relay can add by not saying its length.

### 2.1 The round trip

With keys already swapped, in person or over something you both trust:

1. Your agent runs `auu send --to bob --attach Missing.java`.
2. `auu` signs the record, then seals it.
3. `auu` sends `POST /v1/mailbox/{bob}` to the relay.
4. The relay answers `200`, queued. It holds ciphertext, cannot open it, and
   stores nothing that says it was you.
5. Minutes or days later, their agent runs `auu inbox`.
6. Their `auu` sends `GET /v1/mailbox/{bob}`.
7. The relay answers with a listing of sealed envelopes.
8. Their `auu` opens each one, verifies the signature, and checks that the
   sender is a known peer.
9. When they remove it, their `auu` sends `DELETE`, and the message is gone from
   the relay.
10. The question and its files are handed to their agent, marked as untrusted
    input.

**When they are on another relay**, and yours carries to theirs, steps 3 and
4 become a queue and a second hop. Your agent runs `auu send --to
'bar!bob'`, where `bar` is what *your* relay's operator calls theirs.

3. `auu` sends `POST /v1/forward` to your relay, with the sealed envelope and
   the rest of the address.
4. Your relay answers `201` with the id of a row in its queue. It has taken
   the message and not delivered it: one row and one file, naming you as the
   poster, because mail that cannot be delivered has to be somebody's for
   anyone to be told about it.
5. Its worker dials `bar` as a user of it — a relay forwards by having an
   identity there, its courier — and posts the same envelope, byte for byte,
   to `bar`'s own forward route with what is left of the address.
6. `bar` has nothing left to travel, so it delivers into Bob's mailbox, with
   the hops the message came by written beside the row. Whether Bob accepts
   it is his allow list's answer about *your relay's courier*, not about
   you: `bar` cannot read the envelope, so the only sender it can prove is
   the relay that handed it over. Admitting a courier admits everybody
   behind that relay, and it is the one place a list means something coarser
   than the fingerprints in it.
7. Your relay's row is now `handed`. Its file and Bob's fingerprint go at
   once. The poster, your relay's name for `bar`, and the address stay while
   something could still come back about it. `auu queue` is what you read,
   and `auu inbox` says one line while anything is waiting.

Bob's listing then carries `via`, the relays it came through, and his reply
goes back along that address reversed, without his asking. That reversal
rests on a convention: the names in `via` are each hop's own for the hop
before it, out of its couriers file, while a reply's address is resolved
against the courier home a relay dials from. An operator is meant to use one
name in both, and a relay says at its start which names appear in one and
not the other, but nothing can enforce it and one-way peering is a thing an
operator may want. So where the convention holds the reply routes, and where
it does not the first hop refuses it and `auu` says so, offering `--via` and
`--relay` as the ways to answer anyway.

The `DELETE` at step 9 is the interesting one. The message leaves the relay
only after it is safely on local disk. Crash anywhere in between and you fetch
it twice, never zero times. It happens at the fetch only for a channel you
have set to `off` with [`auu channel keep`](client.md#14-channels). By
default a channel keeps its mail, so the fetch leaves it queued. The
`DELETE` is then what [`auu rm`](client.md#15-receive) sends when you
remove it.

The answer at step 7 lists what is after this machine's cursor, each id
above the one before, and, beside it, how many messages the mailbox holds
in all (`queued`) and the lowest and highest ids among them (`first` and
`last`, both 0 for an empty mailbox, read from the rows in the same
transaction as the page). All three are required, and a listing without
one is refused by name, as is a page whose ids do not rise from the
cursor.

A cursor above `last` is past everything the relay holds. That happens on
an ordinary day, when the newest mail kept on the relay is removed, and
when the relay's numbering began again because its operator deleted its
database. An upgrade does not do it: a relay carries its database forward.
The client tells the two apart by what the relay holds. It lists the
mailbox without envelopes and matches each row to what this machine has of
that relay by the relay's id, the time the relay received it and its size.
When every row matches, the cursor is set to `last` and nothing is said or
downloaded. When one does not, the cursor is set before `first` and the
mailbox is fetched again in the same run. A message this machine already
holds is met by its own id rather than saved, so its record, read mark and
all, stands, and one it let go from the relay is acknowledged again. What
the fetch does not meet is marked as no longer on the relay, so nothing
asks the relay for anything under an id that may now name other mail. Then
it says `relay.example: this machine's cursor was 9 and the relay's mail is
numbered 1 to 3, so the cursor was reset and mail is fetched from the
beginning; nothing is delivered twice here`.

The count is routinely larger than what is listed, since by default a
channel keeps its mail, which is counted but not listed after the cursor.
The client subtracts what this machine deliberately left on the relay before
it judges the rest. When the list is empty, the cursor is inside the span,
and the count still exceeds that, the cursor has skipped mail in the middle.
That is set by hand or copied from a machine that had fetched further. It
is not put right by itself: the cursor is a person's to set, and nothing
from the relay can say whether the gap was meant. Then `auu inbox` says so,
with the count and `auu cursor reset --relay NAME`, which says what the
next fetch will fetch before it writes the cursor. Since every fetch meets
the mail it already has, a fetch from the front delivers nothing twice. It
exits 5 without acknowledging anything or moving the cursor.

Each message listed says which channel it is under (`channel`), always,
`default` included, held to the channel name rule as it is read. It says
how it came, too: `via`, the relays it crossed before the one holding it,
nearest the sender first and joined by `!`, always present and empty for
mail posted to that relay directly. A client holds those names to the same
address rule every relay ran — a relay name each, none named twice, at
most 32 of them — and refuses a row that breaks it by name, since an
address that reached a client having broken it came through a relay that
did not run it. It says its kind too (`envelope`, `stream` or `knock`).
The listing says the state of the owner's allow list (`allow`), of their
card (`card`) and of their channel directory (`directory`) on every answer
— the same three words for each, `signed`, `none` or `broken` — since each
of the three is verified where the relay acts on it and a broken one
refuses something on the owner's behalf that they would otherwise learn of
only from silence: a broken allow list every sender, a broken card every
knock, a broken directory every post.

**Nothing on the wire is from before, and what comes after has one door.**
v0.15.0 is the floor: everything is upgraded to it once, together, and
nothing from before it is supported. So a field one end always sends is
required by the other and refused by name when it is absent, with nothing
of the answer used, rather than read as a peer from before the field. A
listing without `channel`, `kind`, `allow` or `card`, a health answer
without `max_bytes`, `knock_max_bytes`, `registration` or `wire_level`, a
card answer without `state`, a lookup without `created`, a status without
`registration` or `client_certs`, and a refusal without `code` are each
refused so. Neither end carries a branch for an older peer. What a newer
build adds after the floor goes through `sections`, which every message,
manifest, answer and request carries and every reader of this build was
written to read: a part it does not know it ignores, and a part marked
critical it refuses by name, saying that the reader, this machine or the
relay, needs a newer auu, rather than read the rest with that part
dropped. A part is known on the path it is read on and nowhere else: a
name this build reads only on another path is one it does not know on
this one, a request's or an answer's on a message or a manifest, a
request's on an answer and an answer's on a request, so a critical one
there is refused as needing a newer auu, never opened past in silence
with its data unread. Whoever reads a message, a manifest, a request or
an answer understands every critical part on it. A message that needs a
newer auu is kept under `damaged/` with the cause `newer` and the
section's name, and is not deleted: updating auu
and opening it with `auu damaged reopen` is what to do about it, and asking
the sender to send it again is not. That is the one cause for which
anything under `damaged/` is ever opened again. The outer envelope a relay
reads is four fields for good, and a relay carries an envelope whose
version it does not know, since what the version means is between the
sender and the recipient. The relay's
`wire_level` on its health answer says what it can do. And a refusal is
told apart by its `code`, never by its words, so a relay may change its
words and add codes without a client misreading either.
[`docs/client.md`](client.md) says what this means for a person upgrading,
and the release note [`docs/releases/v0.15.0.md`](releases/v0.15.0.md)
gives the order.

**Nothing on this machine is from before** either. A file a version from
before a rule wrote is refused by name with a sentence saying what to do,
never migrated and never read under the old rule, where the version is one
before v0.15.0. A file v0.15.0 or later wrote is read by every later
build, so a later build adds to a kept file's shape only in a way the
older file still reads. A relay's database from before schema 11, a home's
`config.json` of the shape from before it could know more than one relay,
a record with no relay name, and an `auu-ca` key file that is not
encrypted are each refused so. The relay's database is the one file
carried forward, from schema 11 on, since a relay was running on it when
the schema next changed: a step per version, each what that version added
and nothing else, after a copy of the database is kept beside it for the
way back. That copy is a snapshot of every row the database held at the
upgrade, the mailboxes, certificates and tokens among them, and nothing
the relay does afterwards reaches it: a mailbox deregistered, a token
spent or revoked, a row deleted under `secure_delete`, each is still in
the copy. It is mode 0600 beside the database, and it is the operator's to
remove once the new release has run as they want.

Two routes carry a mailbox's channel directory, the signed list of named
sub-mailboxes an owner defines. The owner pushes it with `PUT
/v1/mailbox/{fp}/channels` as the document bytes and the signature over them
(`document`, `signature`). The document is at most 512 KiB — a directory
at every maximum is 425,934 bytes as `auu` writes it — a rule both ends
run before the signature is checked, since a directory padded to the
route's cap would otherwise be verified whole on every post to the
mailbox and on every administrator's page. The relay verifies the
signature against the registered key before storing either. It answers
`401` for one that does not verify, `400` with the rule broken or the
document over its bytes, and `409` for a directory issued no
later than the one it holds, naming when that was issued — a stored row
that no longer verifies being no bar, whatever issue time an editor left
on it, since the relay verifies the stored row before its time can refuse
a push and holds the push to the time inside the verified document. Right
after the signature verifies, and before anything is stored, the relay
holds `issued` to its own clock: a directory issued more than five minutes
(the request skew) ahead of it, outside the years 0000 to 9999 the relay
can write, or outside about 1677 to 2262, which a watch carries as
nanoseconds, is answered `400` with no refusal code, as is a channel
whose `not_before` or `not_after` lies outside the years 0000 to 9999.
The sentence is the reason: it names `issued` and the time, saying for
the first that it is by this relay's clock, or names the channel and its
`not_before` or `not_after`. Before this release, a directory signed
under a clock far ahead was stored, and every later push from a machine
with the right clock was refused as older until that instant passed: one
wrong clock jammed the owner's own policy. A held directory issued more
than five minutes ahead of the relay's clock is therefore no bar: while
it is held, any directory the key holder signed that passes the bound
replaces it, the guard against an older push suspended for that one
push, which only the key holder could have brought about. A relay
holding such a row, stored by an earlier release, recovers at the
owner's next push with no operator. The allow list and the card are
held the same way. One thing outlasts a directory's recovery: another
machine of the owner whose `channels.json` holds the future issue time
has its guard against writing over a newer directory off until that time
passes, since its edit's preflight finds nothing a relay holds issued
later than its own, so after the recovery that machine should run `auu
channel pull` before it edits. A running `auu watch` is woken by the
replacement as by any change. `auu` runs the same check as the relay
before it sends anything. A directory already stored is read as it is,
since a bound at the read would close a mailbox over a clock. A row an
earlier release stored with an issue time the relay cannot read back, a
year -1 in UTC, is held as it is, its issue read as the zero time and
said in the relay's log once a minute, so every watch that asks goes on
working and the owner's next push replaces the row.

Anyone the allow list admits fetches it with `GET
/v1/mailbox/{fp}/channels` and gets the same two fields back verbatim, to
verify against the key they hold for the owner. A sender the allow list
refuses gets the refusal a post would, and learns nothing about channels. A
mailbox whose owner has pushed none answers `404` with
`no directory: the mailbox has the one channel, default`. A courier's
mailbox answers every caller `403` with the post's refusal instead, as a
post, a stream and a forward delivered into it are answered. That tells
its callers nothing new: each is a registered identity of this relay, and
`GET /v1/couriers` lists every courier's fingerprint to all of them. What
the `403` keeps is the same face on every route, so that no route only
this relay's users reach sets a courier's mailbox apart beside the one
silence that matters, a forward's delivery, whose answer a sender on
another relay with no mailbox here reads through the forward's report.
`docs/relay.md` section 1.10 says why.
The owner's own fetch adds `queued`, how many messages wait under each
channel. Nobody else's does.

The allow list travels the same way. `PUT /v1/mailbox/{fp}/allow` carries
two fields, `document` and `signature`, the list as the owner signed it
under its own domain, and at most 128 KiB of them — a list of a thousand
fingerprints is 67,141 bytes as `auu` writes it — the same rule run in the
same places, before the signature.
The relay verifies the pair against the registered key before storing
either. It answers `401` for a signature that does not verify, `400` with
the rule broken, the document over its bytes, or `issued` more than five
minutes ahead of its clock or outside the years 0000 to 9999, as for the
directory, and `409` for a list issued no later than the one it holds, a
broken row being no bar. A body with no document is answered `400 this
relay takes a signed allow list; the request carries no document`, which
stores nothing. The owner reads it back with `GET
/v1/mailbox/{fp}/allow`. That answer is the pair verbatim and `state`,
one of `signed`, `none` and `broken`. `none` means never pushed, and any
registered sender may post. `broken` means it does not verify, a row
with no signature included, and every sender but the owner is refused.
The owner's own mailbox listing carries the same word as `allow` on
every answer.

The card travels the same way. `PUT /v1/mailbox/{fp}/card` carries
`document` and `signature`, the card as the owner signed it under its own
domain, `ccx-card-v1`, and is read under the general 64 KiB cap. The
document is `v`, `owner`, `issued`, `name`, `listed` and `knocks`, the
name under the export line's rule, and at most 512 bytes — a card at
every maximum is 199 as `auu` writes it — a rule both ends run before
the signature is checked, since a card padded to the route's cap would
otherwise take every reader's page of the listing over its hold. The
relay verifies the pair against the registered key before storing
either, and answers `401` for a signature that does not verify (a body
with no document included), `400` with the rule broken, the document
over its bytes or naming another owner, or `issued` more than five
minutes ahead of its clock or outside the years 0000 to 9999, as for the
directory, and `409` for a card issued no later than the one it holds, a
broken row being no bar. The owner reads it back with `GET
/v1/mailbox/{fp}/card`, the pair verbatim and `state`, one of `signed`,
`none` and `broken`, and their own listing carries the word as `card`.

Any registered, unblocked identity — a
mailbox, not a certificate alone — fetches the cards that say listed
with `GET /v1/listed?after=FP&limit=N`: a page of `entries`, each the
`bundle` the relay verified the card against at the push, the
`document` and the `signature` as stored, in fingerprint order from
`after` exclusive, at most `limit` of them, `limit` held to 1 to 100 and
refused outside it, and `listed`, how many such cards the relay holds in
all. Blocked owners are left out. The relay verifies nothing on the way
out. The reader verifies every entry — the bundle parses, its
fingerprint is the document's owner, the signature verifies under its
key, the document says listed, and the fingerprints rise — and drops
what fails, refusing an answer whole that breaks the order or carries
more than it asked for, and a full page from which nothing could be
paged past. A page is held to 256 KiB, which a hundred cards at their
cap fit under, and the whole listing to ten thousand entries served,
verified or not.

The health answer, unsigned and served to
anyone, carries the relay's registration mode as `registration`, one of
`open`, `token` and `closed`: it is what admission to the relay means,
and a client prints it wherever it shows a name it found there, since a
relay that lies about its mode is admitting anybody, which is the case
the word warns of.

A vouch never reaches a relay as itself. It is one peer's word that it
holds another, signed under its own domain, `ccx-vouch-v1`: the document
is `v`, `voucher`, `subject`, `bundle` (the subject's, whose fingerprint
must be `subject`), `name` (the voucher's label for the subject, under the
export line's rule) and `issued`, every field always written, unknown
fields and trailing bytes refused, the voucher never the subject, and at
most 2,048 bytes — a vouch at every maximum is 1,958 as `auu` writes it —
held before the signature as a card is. It travels only inside a sealed
message: a message of type `vouch` carries one as `vouch`, the document
and the signature as signed; a message of type `vouch-ask` names the
fingerprint it asks about as `about`; and a knock may carry up to four as
`vouches`. Each field is refused by name on any other type, at the open
and when a stored record is read back, and neither type is ever a stream.
An issue time more than forty-two minutes ahead of the reader's clock is
refused, as a message's is, by the chain of clocks given below. What the
relay sees is an ordinary post.

A message posted to a channel names it in the clear, as `ch` on the outer
envelope at step 3 and `channel` on the request that opens a stream. The
relay reads it after the allow list has admitted the sender and before
anything is stored or charged to the recipient's mailbox. The sender's own
budgets, posts a minute and bytes an hour, are spent before either check.
So a refused post costs the relay little, and a sender the list refuses
learns nothing about channels. The relay refuses `404 no such channel "x"`
for a name the directory does not hold (`default`, for a mailbox with no
directory). It refuses `403 channel "x" is not open: opens T` or `closed T`
for one outside its period, judged by the relay's clock with both edges
inclusive. A stream's channel, and its sender's place on the allow list,
are judged again at every attempt and before the placement, so a channel
that closes while an upload is open ends the upload at its next attempt
with the same refusal, and one that closes mid-attempt places nothing.
The sealed record and the signed manifest carry the same name,
so a message the relay filed elsewhere is found out on opening. Absent
means `default` everywhere. That is the sender's rule, a message for
`default` carrying no name, and the one place on the wire where absence
means something other than a refusal.

The sealed record carries a time, and it is the sender's word alone. It is
shown, labelled as theirs, and orders nothing but a last tie. A thread's
order is the receiver's. It goes by when each message arrived here, by
this machine's clock, then by the relay's counter. So a peer cannot stamp
a message into being the latest on a thread and draw every reply by
thread to it. The relay's `received` is its own clock's word: it is
shown, and in this order it only breaks a tie after the counter, so a
relay with its clock ahead cannot pin its message atop the inbox or a
thread. The inbox and a thread's latest take this one order, and serve's
opener takes it as far as its ledger keeps it: arrival here, then the
relay's counter. A message an earlier release kept here counts as
arriving at its `received`, or, if that cannot be written back or is
more than five minutes ahead of this machine's clock, when its file was
last written, held to the same two, and otherwise now. The one bound on
the stamp is the future. A message may be old, since it was stored and
forwarded. But one stamped too far past the receiver's clock is refused
at open as malformed, on the envelope and on the manifest alike, and a
vouch's `issued` is held to the same bound.

The bound is the chain of clocks the stamp crossed, each held to the
next. The sender's clock is within five minutes of its relay's on the
post. Each relay's is within a minute of the next one's on a courier's
request. The last relay's is within five minutes of the receiver's on
the listing's `received`. So the bound is twice five minutes and a
minute for each hop: eleven minutes over one courier hop, eighteen at
the default `courier.max_hops` of 8, and forty-two over the protocol's
thirty-two, which is the bound every client holds, compared in whole
seconds as a request's freshness is. It is not the request's five
minutes, because two honest peers on one relay may differ by twice
that: alice four minutes ahead of the relay and bob four behind are
both accepted, and a bound of five refused alice's message at bob's as
from the future, kept it under `damaged/` and acknowledged it, with
nothing said to alice.

The listing at step 7 takes three more parameters, all optional. `wait=D`
asks the relay to hold the answer until a message arrives after the id asked
from, or `D` elapses, and then to answer the ordinary listing. A relay holds
for at most 60 seconds, clamping a longer `D` rather than refusing it. One
already holding as many listings as `max_waiting` allows, or two for the
same identity, answers at once instead. The hold degrades and never
refuses.

`peers=FP:ISSUED,...` names peers whose channel directories the caller
is watching and the issue time it holds for each, in Unix nanoseconds. A
push that replaces one of them wakes the hold. The answer names in
`directories_changed` every watched peer whose directory has an issue
time different from the one the caller said, never one whose issue the
relay could not read. A peer the caller may not post to is dropped
without a word, never named and never woken on, since the directory
fetch the caller made first has already told it `403`. A courier's
mailbox is dropped the same way, for the reason that fetch refuses it.

`stubs=1` answers every row without its `envelope`, for a caller that
wants the ids and nothing else. That is what checking whether mail it left
on the relay is still there needs, and what stops a mailbox of such mail
being downloaded again on every check. A stubs listing whose row carries
an envelope is refused by the client by name, as a relay that ignored the
parameter.

A large message changes step 7 only. Instead of arriving with the rest of the
mailbox, it is listed as a stream and its body is fetched separately, in
pieces, straight to disk. That is what lets a two gigabyte attachment cross
a relay that never holds more than a buffer of it in memory.

A message that does not open at step 8 is nobody's to read. That is one that
did not decrypt, one that names another recipient, one whose sender does not
hold up, or one that is not an envelope. Leaving it queued would block the
mailbox, so it is acknowledged. But first its bytes are kept under
`damaged/` in your home with the cause in a word. The warning names the
file and says to ask the sender to send it again, and `auu inbox` says how
many are there until you remove them.

A message that opens is filed under the channel it was sealed for, after that
name has been checked against the one on the outer envelope and the one the
relay listed it under. A disagreement is a message the relay filed
elsewhere. It is kept under `damaged/` with the cause word `misfiled`. The
warning says `relay message N was filed under "a" by relay.example.com but
is sealed for "b"; it was kept as PATH`. It is acknowledged like the other
kept messages, so the mailbox is not blocked. A listing that names no
channel for a message is refused by name before anything is filed.

Nothing kept under `damaged/` is opened again, with one exception. A
message kept with the cause `newer` needs a newer auu, not a new copy, and
`auu damaged reopen` opens it once that auu is here. It runs the fetch's
checks on the kept bytes and files what opens as the fetch would have. A
record an earlier release wrote does not say what the relay's listing
said, so for it the kind check cannot run and the channel is checked
against the envelope's own alone. Named
by its relay and id, a message kept for any other cause is refused by name,
since no auu can open it or the check that kept it would keep it again,
and `--all` passes those over. Reopening fetches and acknowledges nothing.
The one thing it can send is the vouch answer a fetch sends, when `auu
vouch answer on` is set.

### 2.2 A large message

Above 64 KiB, `auu send` stops building one envelope and builds a stream. It is
one HPKE context and a run of sealed chunks. The manifest comes first,
saying what the message is and what each file must hash to, then the file
bytes.

On the wire a stream is these, in order. `enc` is the 1120-byte X-Wing
encapsulation. `len0` is four bytes saying how long the manifest is. Chunk
0, sealed, holds the signature and the manifest (subject, text, file names,
sizes and SHA-256 hashes). Then come file bytes in sealed chunks of 63 KiB.
Last is a chunk sealed under the label `final`, after which nothing may
follow. What a manifest may name is what a message may. Each file name is
a base name, and no two of them are one file where case does not count,
since the receiver's disk may fold case. Both ends apply the rule, the
sender's before anything leaves. A pair the rule cannot foresee that the
receiver's disk still spells as one is refused where the file is opened,
as the manifest's fault. Two Unicode normalisations of one name, on APFS,
are such a pair. So the stream is kept under `damaged/` and acknowledged
rather than met again at every fetch.

Three things fall out of that shape:

- **The last chunk is sealed under a different label.** Cut a stream short and
  the chunk the receiver expects to be the last one will not open. Truncation
  is caught by the cipher, not by a length field somebody could lie about.
- **Chunk 0 is enough to decide.** A receiver fetches 1124 bytes plus the
  manifest, learns who sent it and how big it is, and only then agrees to
  download the rest. A stranger cannot make anybody pull two gigabytes.
- **Nothing is ever held whole.** The sender seals a chunk at a time, the relay
  writes each byte to its file as it arrives, the receiver decrypts a chunk at
  a time and writes it straight to a file. Sending a 2 GB file costs about
  20 MiB of memory at each end.

On the wire the upload is three routes. `POST /v1/mailbox/{fp}/streams` opens
it. The signed size and channel charge the recipient's quota and the
sender's byte budget. The sender's count of open uploads is held to the
relay's `max_open_uploads`. At it the open is `429` with a `Retry-After` of
the seconds to the sender's soonest expiry, which the client waits out. The
uploads it opens in an hour are held to `max_upload_opens_per_hour`, and
over that the open is `429` with a `Retry-After` too. The answer is an
upload id, when it expires, and two numbers the sender needs,
`resume_threshold` (bytes, the relay's `max_bytes`) and `resume_window`
(seconds, sixty). `PUT /v1/uploads/{id}` is one attempt. It carries the
sealed stream from an offset to the end in one request, with
`Upload-Offset` saying where it starts and `Content-Length` required and
equal to the bytes left. So an attempt runs to the end or is not an
attempt. Before it reads a byte the relay judges again what the open
judged, the allow list, a courier's mailbox and the channel, and refuses
as the open would, the upload going with the refusal. Then it judges the
headers, still before it reads a byte. No length is
`411`, a length that does not reach the end is `400`, and an offset that is
not where the relay's copy ends is `409` carrying that offset. Then it
streams the body to the upload's file, checking the shape of the first
bytes as they pass. When the last byte lands the allow list and the
channel are judged once more, and only then is the stream placed in the
mailbox and the answer `201` with the message id. `DELETE
/v1/uploads/{id}` lets go of an upload before then.

An attempt that stops short is judged by one rule. That is one whose
sender's link dropped, or whose bytes stopped coming. If it was the first
attempt and what the relay holds is at least the threshold, the partial is
kept for one resume, for sixty seconds from that moment and no longer.
Otherwise nothing is kept, and the upload, its file, its row and its
reservation go together. If the relay had kept a partial before that
attempt, the sender's budget is given back the size less it. If it had
kept nothing, as after a first attempt short of the threshold or one the
relay's own disk failed, nothing comes back and the declared size stays
charged for the hour. A kept partial stays charged while it is kept. So
the relay never holds less than a threshold's worth of an upload that did
not finish. A stream is placed by at most two attempts on one id. A sender
that trickles a byte at a time builds nothing up. A budget is spent on
what the relay holds or places, and on the whole of a reservation that
never held a byte. The sender learns what the relay kept the way
this wire tells it, by the next attempt. One from zero on the same id is
`409` with the kept offset, from which it resumes once. It is `404` or
`410` when the relay has let the upload go, on which it opens anew. It is
simply the fresh attempt when the relay never saw the one that was lost. A
resume after the window is `410`, naming when the upload expired and
saying to open again, with the upload and its reservation gone. An upload
nobody starts an attempt on within ten seconds of its open, the start
window, goes the same way. The answer names the start window only by the
moment it ends, its `expires`: a client of this release knows the window,
and an older one meets the `410`.

Bytes that stop coming, or come too slowly, end inside a window too. The
attempt runs under the relay's own hunk deadline on the connection, which
no setting changes: ten seconds from the attempt's start, set ten seconds
on from the read that completes a whole hunk of 64 KiB since it last
moved, and at no other read. So a transfer of any length finishes while it
keeps a pace of 6.4 KiB a second. A slower or stalled one is cut and
judged by the rule above, its answer written under a fresh deadline of its
own for anyone still listening. A deadline that every byte moved would let
a sender trickle a byte a window and hold a reservation for ever. The
download of a placed stream is served under a stall deadline of sixty
seconds, moved by every write that delivers bytes. So a reader that stops
is cut inside that window. A slow one is served to the end rather than cut
by the server's five-minute write timeout every five minutes and left to
ask by `Range`. The server's five-minute read and write timeouts stand on
every other route. A refusal before the body is read closes the
connection, and the answer is written before any of the body is read. The
standard library then reads up to 256 KiB of what was declared before it
closes, which is the one cost a refused attempt has.

An interrupted upload resumes. The sealed copy stays in `outbox/` and
`auu send --resume` carries on from the byte the relay says it has. That is
also why sending seals to disk first. The nonce counter inside an HPKE
context only goes forwards, so a chunk that was lost could never be sealed
the same way twice. A relay whose disk fills part way through answers
`507`, keeps the partial when the rule above keeps it, and `auu send` says
the sealed copy is kept and to resume when there is room. Downloads resume
too. The blob route honours `Range`, so a receiver that holds the first
part of a stream asks for the rest from there. A range from the end or
past it is `416`.

The client holds the answer to a range to the span it asked for. It must be
`206` with a `Content-Range` for exactly that span. The span's end may be
the file's last byte where the file is shorter or no end was asked for. A
`Content-Length`, when the answer gives one, must be the span's. A relay,
or a proxy or cache between, may ignore `Range` and answer `200` with the
whole blob, since HTTP permits that. Read as the range, that answer would
not open, and the stream would be kept as damaged and acknowledged. That
would delete it from the relay for good. So an answer that is not the
range asked for is a malformed answer naming the relay. It is a transport
failure, never a damaged stream. Nothing is kept under `damaged/` and
nothing is acknowledged. The fetch from that relay stops at the stream,
and the stream and everything after it wait on the relay for the next
fetch. So an intermediary that does not honour a range can no longer make
a stream be deleted unread. One that alters the bytes it carries can, as
the relay can, and TLS to the relay is what keeps anyone else from it.

### 2.3 A knock

A knock is the one message that reaches a mailbox from somebody its owner
has not admitted, and it reaches it only where the owner has said so on
their signed card. On the wire it is an ordinary sealed envelope, sign
then encrypt like every message, posted to a route of its own,
`POST /v1/mailbox/{fp}/knock`, and stored with the kind `knock`. It is a
route and not a field of the post because everything that can be judged
without the body is judged before it, and a kind inside the body would
have the relay read a whole post before learning it was a knock. So the
route has a cap of its own, `knock_max_bytes`, never above 64 MiB, plus
64 KiB of framing, and a body that declares itself over it is refused
`413` before a byte of it is read.

The relay checks, in this order, after the certificate, the auth header,
the identity, the body under the knock cap, the signature and the
knocker's own block: that the envelope is under `knock_max_bytes`, naming
the setting; the post budgets, charged as for any post; that the envelope
parses, is addressed to the mailbox and names no channel, since which
channels exist is the owner's to publish to the senders they admit and a
knocker is not one; that the mailbox exists and its owner is not blocked;
then the card, read from the database and verified against the mailbox's
registered key at that moment, never cached and never read from the
`knocks` column the relay parsed at the push; then the knocker's
`knocks_per_hour`, refused `429` with `Retry-After`; then the store, which
inside the transaction that inserts the row counts the knocks the mailbox
already holds and refuses at `max_knocks_waiting` with a `429` that
carries no `Retry-After`, since the relay cannot say when the owner will
fetch, and gives the knocker's token back.

That cap counts knockers, not knocks. A mailbox holds one knock per
knocker: a second knock from the same key replaces the first, in the same
transaction that counts and stores, so a knocker who got their line wrong
sends it again and a knocker cannot take more than one of a mailbox's
places however often they knock. The replacement is the knocker's own
act, not the relay's choice: the owner sees the earlier id go and a new
one arrive, and if they had already fetched the earlier knock — a fetch
acknowledges every knock — then nothing is there to replace and they
simply have two knocks from one stranger, which is what happened. To
recognise a knocker the relay keeps their fingerprint on the row, for as
long as the row lives and no longer. An owner who would rather it did not
pushes a card that says no knocks.

The allow list is never read on this route, and the card is never read
on the post route.
No card, a card that says no and a card that does not verify are one
refusal, `403 the
recipient does not take knocks`, since the state of somebody else's card
is not a stranger's to learn. The relay's own log says once a minute, under
either access log mode, that the card for the mailbox does not verify,
naming the mailbox and never the knocker.

Sealed inside a knock, where the relay reads none of it, are the knocker's
name, which is their own claim held to the name rule at both ends and
escaped wherever it is shown, and one line of text of at most 512 bytes
with no line break, tab or character a terminal would obey rather than
show. A knock opens a thread and answers nothing, carries no subject and no
attachment, and is never a stream: a manifest that says knock is refused.
