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
exist, or is not open, is refused before the message is stored, and a
directory that no longer verifies closes the mailbox — every name
refused, `default` and the owner's own post included — until they push
again. It closes rather than falling back to `default`, because falling
back would open a name an owner's own document may have removed or
closed, and because that is what a signed thing that no longer verifies
does here: a broken allow list already refuses every sender. The owner is
told at their next fetch, and `auu channel push` is the repair. The owner chooses what the labels say. The kind is one of three words,
`envelope`, `stream` or `knock`, given by the route the message arrived
by and said beside the row in every listing; a knock is a stranger's one
message, taken past the allow list only where the recipient's signed card
says `knocks`, and it says nothing about who knocked, since that is inside
the ciphertext like every sender. Beside the rows, per mailbox, the three
documents an owner signs and pushes: the channel directory, the allow
list, and the card, which says the owner's name and two words of the
owner's, `listed` and `knocks`. Each is the bytes the owner signed and the
signature, verified against the registered key at the push and again
wherever the relay acts on it, and the card's two words are parsed into
columns that decide nothing. The message itself is a file beside the
database, which an operator can list, count and delete but not read.
Every value the relay puts
to that database goes as a query parameter, never into the text of a query.
That is true of a fingerprint, a channel name, a token id and a reason
alike. A test (`internal/sqlshape`) parses the tree and fails on any query
whose text is not a constant.

Since a channel keeps its mail by default, that ciphertext now stays until
its owner removes it rather than until they read it. The relay learns
nothing more from the wait. It never knows a message was read, because
nothing tells it. A fetch is a `GET` of the mailbox. The `DELETE` that
follows says only that the owner is finished with it, whether that is a
second later or a month. What it costs is room, which the per-mailbox
limits bound.

Two rows are exceptions, and both are worth stating. While a stream is being
uploaded, the relay holds a row naming the *sender* as well as the recipient.
It has to, because only the sender may append to their own upload and the
reservation must be charged to somebody. That row lives for the length of one
upload and is deleted when the stream completes or is abandoned, and nothing
survives it.

The other is a knock. A knock row carries the fingerprint of whoever
knocked, and carries it for exactly as long as the row: until the owner's
fetch acknowledges it, until that knocker knocks again and replaces it, or
until the mailbox goes. It has to, because that is what lets a second knock
from one key replace the first, so the waiting cap counts knockers rather
than knocks and no single identity can fill a mailbox's share of it. Nothing
survives that row either: no counter, no log line and no other table keeps
it, and an owner who would rather the relay held no such thing pushes a card
that says no knocks, which closes the door and stores nothing. Those two
rows are the whole of what the relay writes down about who is sending
something.

While an upload's row lives, the reservation counts against the recipient's quotas
and the relay's as though the stream were already queued. That holds for an
envelope posted beside it as much as for another stream. One arithmetic
answers both, so neither can be filled into the other's reservation. What
bounds one identity's uploads is the count, `max_open_uploads`, beside its
byte budget. The count is four unless the operator sets `max_open_uploads`, across every mailbox it sends to. The open
charges the declared size. What the relay never ends up holding comes back
when the upload goes unplaced. So the budget charges what the relay holds,
and an abandoned upload does not spend the hour.

**What the relay sees.** More than it stores, and this is worth being plain
about. Posting is authenticated, so at the moment a message is accepted the
relay knows which identity is writing into which mailbox. Its access log
records exactly that unless you set `access_log: "minimal"`. Rate limiting
keeps the verified fingerprint in memory for as long as a bucket lives.
Anybody holding the logs of a `full`-mode relay holds the social graph. Nothing
of that is written to the database, and no limiter key is ever written
anywhere; the one thing a stored row says about a sender is the knocker on a
knock, above, which lives as long as the knock does. The
channel a message was posted to is the one thing about a message's content
the relay learns beyond its size. It is written to the row, served in the
owner's own listing, and recorded in the access log under neither mode.
A knock is seen as any post is, and stored with one thing more: the row
says `knock` and carries the knocker's fingerprint, which is what lets a
second knock from one key replace the first. What the knocker *wrote* is
inside the ciphertext like every sender's words; what the row holds is
who they are, and only until the owner's fetch acknowledges it, it is
replaced, or the mailbox goes. An owner who would rather the relay held
no such thing pushes a card that says no knocks.

A listing held open (`wait`) tells the relay nothing it did not know. It is
the owner's own listing, answered later. A directory watch (`peers`) tells
it which peers the watcher may post to, which the directory fetch the
watcher made first had already told it. It tells it nothing about a peer
who has not admitted the watcher, since such a peer is dropped before
anything is held. Neither reaches the access log. The query string is not
logged under either mode. And there are no delivery receipts for an
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
command can forget. What a peer writes is held to the same standard twice
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
administrator is reading carefully. And what the relay lists is checked
for shape before it is used. Every fingerprint, serial and token id in an
answer is held to its rule as it comes off the wire. A lifetime it reports
in seconds is bounded before anything multiplies it. Every count it
reports is zero or more, every message id one or more, a parameter set one
of the three, and an upload's offset a byte count. So an answer with a
two-byte fingerprint or a negative queue is refused whole as malformed,
naming the field and the relay. It is not sliced by a command that
expected sixty-four characters or seeked to by one that expected an
offset. Every integer that enters the program from outside has a row in
`internal/limits/ledger.txt`, and so does every slice of a string or a
byte slice. An integer from outside is a field in a JSON shape, a number
or a duration parsed from text, a length read from four bytes, or a flag.
For an integer, the row gives the range the code holds it to and the test
that takes it to the edge and one step past. For a slice, it gives the
rule that fixed the operand's length and the point it ran, with the test
that feeds the operand one byte short there, or the operand's own
arithmetic. The test beside the ledger walks the tree and fails on a site
with no row. A record read back from the home is held to the shapes a
print slices at the point it is read. Those are a message's ids,
fingerprints and digests at `Load`, a relay's pinned hashes, a
certificate's serial, and an outbox record's id and recipient. So a file
this program could not have written is refused with the file named rather
than cut.

A stream from somebody who is not in `authorized_peers` is never downloaded.
The receiver fetches the 1124-byte header and the signed manifest, sees who it
is from, and stops. The body stays on the relay until a person runs
`auu quarantine trust`. A stranger cannot make anybody pull two gigabytes.
What they can make a receiver keep is the manifest record in quarantine.
The first chunk it came in is capped at 1 MiB, so the disk they can spend
is bounded by that.

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
reading a column the push wrote, and a mailbox that has never pushed one
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

**Enrolment tokens.** Signed by the issuing administrator's own identity key,
so the relay holds no new private key material. Removing an administrator
from the authorized file invalidates every token they issued. A token must also
be registered with the relay before it can be redeemed, which is what makes
revocation and single use real rather than hoped for. Tokens are bearer
credentials. Send them over TLS. The relay's audit log records a token's id and never the token. The relay does
not record which token created which mailbox. That link appears once in the
operator's audit log and nowhere in the database, because a permanent table of
who invited whom is a social graph of a different kind.

**The allow list.** Owner-signed, like the channel directory. `auu allow
push` signs the list of who may post to you with your identity key. The
relay verifies the signature against your registered key before storing
it and again on every post, with no cache. A row edited in the relay's
database therefore refuses every sender but the owner rather than admitting one. A
sender is told what a refused sender is always told. Your own listing says
`broken`, `auu inbox` says so, and your next `auu allow push` is the whole
repair, whatever issue time an editor left on the row, since the
newer-issued rule holds only between two lists you signed. A row with no
signature is broken too. A signed row with its
signature removed refuses every sender but the owner at once. There is no state in
which the relay honours a list it cannot verify. So a restricted mailbox
whose list does not verify is closed until its owner pushes, and `auu
inbox` tells them so on every fetch. Your own machine also remembers that
it pushed a signed list, and says so if the relay's row has gone
altogether. What this does not cover is root on the relay's host, who can
replace the relay itself. That is where *What is not protected* below
draws the line. The signature moves the bar from editing one table to
replacing the binary.

**The card.** Owner-signed, the third document. `auu card push` signs
your name and two words, `listed` and `knocks`, with your identity key,
and the relay verifies the pair against your registered key before storing
it. A row edited in the relay's database stops verifying, and a card that
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
fingerprints with people directly. The card listing is a second way a
person may choose to fill the file, and it rests on exactly one thing:
who the relay admits. The relay can prove, and the client checks, that a
listed bundle hashes to its fingerprint and that its card was signed by
the key inside it; that is a statement about bytes, and the client
verifies every entry itself, dropping what fails, so an edit to the
relay's database removes a name and never adds one. What the relay
cannot prove is that a fingerprint belongs to a person. On a relay that
invites by token, a listed identity was let in by an administrator who
signed the token, and its name is its own claim; on one that registers
anyone, an identity proves nothing about who holds it. So a peer taken
from the listing is trusted as far as the relay's admission is, and no
further, and `auu peers fetch`, the one
command that adds from it, prints which kind of relay it is before it
asks, at a terminal, and never without a person. The name on a card is
the owner's claim, offered at the prompt as the local name and never
taken as one until the person accepts it. A relay that lies about its
mode is admitting anybody, which is the case the sentence warns of.

A knock is the one message that crosses without an entry, and it adds
none. `auu knock` reaches somebody whose card says they take knocks, and
what it buys the knocker is a sealed line in the other person's
quarantine, where every stranger's message goes. One: `auu knock` sends
one and then refuses, since the person is a peer by then. The relay does
not count them — it has no memory of who knocked — so what bounds a
knocker who is not running this client is the operator's two settings,
`max_knocks_waiting` on the mailbox and `knocks_per_hour` on the sender. Nothing on the knocked
side is trusted by its arrival: the name the knock carries is the
sender's own claim, shown as theirs, offered at the prompt when somebody
runs `auu quarantine trust` and never taken as a label until a person
accepts it. On the knocking side the peer being added is that person's
own decision, asked for at a terminal before anything is sent, which is
why neither `knock` nor `peers fetch` is a command the skills run.
The one identity trusted without an entry
is your own. A message you sent yourself is opened, verified and delivered
like any other, and the relay accepts it for your mailbox whatever your allow
list says. Sender
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
manifest, a channel directory, an allow list, a card, a token, or any
request that
posts, uploads, registers, pushes or administers, a knock among them: a
knock is a message and its route originates, so an agent unlocked to
receive refuses it twice over, exit 4 with nothing sent. Anything it does not
recognise is refused too. `auu unlock --send` is everything, and then back
to receive. It asks the passphrase again, and its window is ten minutes by
default. An induced action in receive scope can therefore fetch mail and
acknowledge it, which is to say delete it from the relay. It can renew
this machine's own certificate, and nothing more. The relay issues that
certificate to the signing identity's fingerprint and to no other, on the
live certificate it then retires, with no token and for no other machine,
so it is maintenance and not an act. In a send window it can originate as
the person, which is why the window is short and typed for.
This does not reach a home that was never encrypted, whose keys are files
any process can read. Nor does it reach one whose passphrase is in a file,
which the AI can read too. The one accepted exception is `auu serve`. An
expert originates unattended by design, to the channel it serves, and is
unlocked with `--send --ttl 0` on a machine that is nobody's desktop. Serve
refuses to start under receive scope and says so.

## 2. The wire, in detail

What the relay stores for one message is three fields, and a fourth on a
named channel. `v` is the format version. `to` is the recipient's
fingerprint. `ct` is about 4 KiB of ciphertext for a short message. `ch` is
the channel, omitted for the default one. Sealed inside `ct`, where the
relay cannot read a byte of it, are the Ed25519 signature, the sender's
fingerprint and public keys, the subject, thread, message id and time, the
text, and any attachments. Sign-then-encrypt, so the signature is inside
the box. The relay sees that you posted to Bob, and stores no sender —
except on a knock, whose row names its knocker for as long as the row
lives, which is the one exception above.

The message id, the thread and, on a reply, `in_reply_to` are each a
message id. That is 32 lowercase hex characters, the id of the message that
opened the thread or that is being answered. That is a rule of the format,
not a convention. A record whose id, thread or `in_reply_to` has any other
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
host's serve directory. It is a message id at open, in a manifest, and
checked again by `auu serve` before it is joined onto anything. One test
walks every one of them with `..`, `../x`, `x/../../y`, `a/b`, an
absolute path, a backslash form, a drive letter, a drive-relative name,
a Windows device name with and without an extension, a NUL, the empty
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

**The HTTP layer has bounds of its own**, and they are not settings. The
relay speaks HTTP/1.1 alone. HTTP/2 is off on the listener and not offered
by ALPN, so a client offering `h2` is answered over HTTP/1.1. Every
property below holds under the one protocol the relay's tests run rather
than a second one with its own stream, reset and header semantics. Those
properties are the refusal before the body, the drain, `Connection:
close` behind a refusal, and the stall deadline on the connection. The
request line and headers together are capped at 32 KiB, answered `431` by
the standard library before the relay sees the request. The largest header
the protocol carries, the request signature, is Ed25519 and about 200
bytes. The relay refuses an auth header longer than its five fields can be
before it cuts a field from it. Every body is read under the cap of its
route. A post is read at `max_bytes` plus 64 KiB of framing. An allow list
or a channel directory is read at 1 MiB, sized to the documents' own
maxima on the wire. Every other request is read at 64 KiB, a card among
them, since one at its maximum is a few hundred bytes. A body that
declares itself over the cap is refused `413` before a byte of it is read,
the sentence naming the cap. The stream `PUT` is bounded by the size its
open declared. On every authenticated route the order is the certificate,
the auth header parsed, the identity it names looked up, then the body,
then the signature, the stream PUT excepted, whose signature is over an
empty body and comes before it. Everything that can be judged without the body is
judged before it, so a stranger's sixteen megabytes are refused unread.
The signature comes after the body because it is over the body. Every
refusal before the body closes the connection behind its answer, the
`413`, the `401` and the in-flight `503` alike. The standard library would
otherwise read up to 256 KiB of the body the handler declined before
writing the answer on a connection it meant to keep, and wait for a body
that never came. That is what a refusal that leaves the body unread must
not do.

The client holds the same bounds from its side. Its transports offer
http/1.1 alone by ALPN and never attempt h2. A response's headers are
capped at the same 32 KiB, and a relay whose answer runs past it is
refused as a malformed answer. A JSON answer is read under twice the
default `max_bytes`. A listing page, the one answer that grows with the
relay's setting, is read under twice the relay's own `max_bytes`. The
relay says that figure in its health answer, and the client learns it
once. It asks again only when a page is refused for its size, in case the
setting was raised under a client that runs for days. The relay's page
follows the same figure, so the two agree. A relay that does not say its
`max_bytes` is refused by name. A stream route's answer, the placed
stream's id or an error's sentence, is read under 64 KiB. The trust anchor
answer is read under 1 MiB. Each is refused by name over it, the same rule
and not a cut that fails later as JSON. A directory or an allow list is
held to the 1 MiB cap before a byte is sent. The stream routes run on a
client with no whole-exchange timeout and a stall rule of the relay's
sixty seconds on both bodies. A two-minute whole-exchange timeout, under
the one-request wire, meant a stream needing more than about four minutes
on the link could never be placed. An upload the relay stops taking, and a
download the relay stops sending, are cut with a sentence naming the
stall. The next attempt or the next range picks up from where the relay's
copy ends.

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

The `DELETE` at step 9 is the interesting one. The message leaves the relay
only after it is safely on local disk. Crash anywhere in between and you fetch
it twice, never zero times. It happens at the fetch only for a channel you
have set to `off` with [`auu channel keep`](client.md#14-channels). By
default a channel keeps its mail, so the fetch leaves it queued. The
`DELETE` is then what [`auu rm`](client.md#15-receive) sends when you
remove it.

The answer at step 7 lists what is after this machine's cursor and, beside
it, how many messages the mailbox holds in all (`queued`). The count is
routinely the larger, since by default a channel keeps its mail, which is
counted but not listed after the cursor. The client subtracts what this
machine deliberately left on the relay before it judges the rest. When the
list is empty and the count still exceeds that, the cursor is past mail,
set by hand or copied from a machine that had fetched further. Then `auu
inbox` says so, with the count, the cursor file to delete and the `auu inbox
--relay NAME` to run after. It exits 5 without acknowledging or writing
anything. Each message listed says which channel it is under (`channel`),
always, `default` included, held to the channel name rule as it is read.
It says its kind too (`envelope`, `stream` or `knock`). The listing says the state
of the owner's allow list (`allow`), of their card (`card`) and of their
channel directory (`directory`) on every answer — the same three words for
each, `signed`, `none` or `broken` — since each of the three is verified
where the relay acts on it and a broken one refuses something on the
owner's behalf that they would otherwise learn of only from silence: a
broken allow list every sender, a broken card every knock, a broken
directory every post. **Nothing on the wire
is from before.** Every released version is retracted and no peer from
before this batch is supported. So a field one end always sends is
required by the other and refused by name when it is absent, with nothing
of the answer used, rather than read as a peer from before the field. A
listing without `channel`, `kind`, `allow` or `card`, a health answer
without `max_bytes` or `registration`, a card answer without `state`, a
lookup without `created`, and a status without `registration` or
`client_certs` are each refused so. Neither end carries
a branch for an older peer. The wire has one version, this one, and a peer
from before it is refused by name at the first exchange. **Nothing on this
machine is from before** either. A file a version from before a rule wrote
is refused by name with a sentence saying what to do, never migrated and
never read under the old rule. A relay's database at another schema
version, a home's `config.json` of the shape from before it could know
more than one relay, a record with no relay name, and an `auu-ca` key file
that is not encrypted are each refused so.

Two routes carry a mailbox's channel directory, the signed list of named
sub-mailboxes an owner defines. The owner pushes it with `PUT
/v1/mailbox/{fp}/channels` as the document bytes and the signature over them
(`document`, `signature`). The relay verifies the signature against the
registered key before storing either. It answers `401` for one that does
not verify, `400` with the rule broken, and `409` for a directory issued no
later than the one it holds, naming when that was issued — a stored row
that no longer verifies being no bar, whatever issue time an editor left
on it, since the relay verifies the stored row before its time can refuse
a push and holds the push to the time inside the verified document. The
relay never bounds `issued` against its own clock. So an owner who signs
one far in the future locks their own other machines out of pushing until
they push a later one, or deregister. Only the identity key can do that,
to itself.
Anyone the allow list admits fetches it with `GET
/v1/mailbox/{fp}/channels` and gets the same two fields back verbatim, to
verify against the key they hold for the owner. A sender the allow list
refuses gets the refusal a post would, and learns nothing about channels. A
mailbox whose owner has pushed none answers `404` with
`no directory: the mailbox has the one channel, default`. The owner's own
fetch adds `queued`, how many messages wait under each channel. Nobody
else's does.

The allow list travels the same way. `PUT /v1/mailbox/{fp}/allow` carries
two fields, `document` and `signature`, the list as the owner signed it
under its own domain.
The relay verifies the pair against the registered key before storing
either. It answers `401` for a signature that does not verify, `400` with
the rule broken, and `409` for a list issued no later than the one it
holds, a broken row being no bar. A body with no document is answered `400 this relay takes a signed
allow list; the request carries no document`, which stores nothing. The
owner reads it back with `GET /v1/mailbox/{fp}/allow`. That answer is the
pair verbatim and `state`, one of `signed`, `none` and `broken`. `none`
means never pushed, and any registered sender may post. `broken` means it
does not verify, a row with no signature included, and every sender but
the owner is refused. The owner's own mailbox listing carries the same word as `allow`
on every answer.

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
over its bytes or naming another owner, and `409` for a card issued
no later than the one it holds, a broken row being no bar. The owner
reads it back with `GET /v1/mailbox/{fp}/card`, the pair verbatim and
`state`, one of `signed`, `none` and `broken`, and their own listing
carries the word as `card`. Any registered, unblocked identity — a
mailbox, not a certificate alone — fetches the cards that say listed
with `GET /v1/listed?after=FP&limit=N`: a page of `entries`, each the
`bundle` the relay verified the card against at the push, the
`document` and the `signature` as stored, in fingerprint order from
`after` exclusive, at most `limit` of them, `limit` held to 1 to 100 and
refused outside it, and `listed`, how many such cards the relay holds in
all. Blocked owners are left out. The relay verifies nothing on the way
out; the reader verifies every entry — the bundle parses, its
fingerprint is the document's owner, the signature verifies under its
key, the document says listed, and the fingerprints rise — and drops
what fails, refusing an answer whole that breaks the order or carries
more than it asked for, and a full page from which nothing could be
paged past. A page is held to 256 KiB, which a hundred cards at their
cap fit under, and the whole listing to ten thousand entries served,
verified or not. The health answer, unsigned and served to
anyone, carries the relay's registration mode as `registration`, one of
`open`, `token` and `closed`: it is what admission to the relay means,
and a client prints it wherever it shows a name it found there, since a
relay that lies about its mode is admitting anybody, which is the case
the word warns of.

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
inclusive. The sealed record and the signed manifest carry the same name,
so a message the relay filed elsewhere is found out on opening. Absent
means `default` everywhere. That is the sender's rule, a message for
`default` carrying no name, and the one place on the wire where absence
means something other than a refusal.

The sealed record carries a time, and it is the sender's word alone. It is
shown, labelled as theirs, and it orders nothing. A thread's order is the
receiver's. It goes by when each message arrived here, then by the relay's
counter. So a peer cannot stamp a message into being the latest on a
thread and draw every reply by thread to it. The one bound on the stamp is
the future. A message may be old, since it was stored and forwarded. But
one stamped more than the request skew (five minutes) past the receiver's
clock is refused at open as malformed, on the envelope and on the
manifest alike.

The listing at step 7 takes three more parameters, all optional. `wait=D`
asks the relay to hold the answer until a message arrives after the id asked
from, or `D` elapses, and then to answer the ordinary listing. A relay holds
for at most 60 seconds, clamping a longer `D` rather than refusing it. One
already holding as many listings as `max_waiting` allows, or two for the
same identity, answers at once instead. The hold degrades and never
refuses. `peers=FP:ISSUED,...` names peers whose channel directories the
caller is watching and the issue time it holds for each, in Unix
nanoseconds. A push that replaces one of them wakes the hold. The answer
names in `directories_changed` every watched peer whose directory is
issued later than the caller said. A peer the caller may not post to is
dropped without a word, never named and never woken on, since the
directory fetch the caller made first has already told it `403`. `stubs=1`
answers every row without its `envelope`, for a caller that wants the ids
and nothing else. That is what checking whether mail it left on the relay
is still there needs, and what stops a mailbox of such mail being
downloaded again on every check. A stubs listing whose row carries an
envelope is refused by the client by name, as a relay that ignored the
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
answer is an upload id, when it expires, and two numbers the sender needs,
`resume_threshold` (bytes, the relay's `max_bytes`) and `resume_window`
(seconds, sixty). `PUT /v1/uploads/{id}` is one attempt. It carries the
sealed stream from an offset to the end in one request, with
`Upload-Offset` saying where it starts and `Content-Length` required and
equal to the bytes left. So an attempt runs to the end or is not an
attempt. The relay judges the headers before it reads a byte. No length is
`411`, a length that does not reach the end is `400`, and an offset that is
not where the relay's copy ends is `409` carrying that offset. Then it
streams the body to the upload's file, checking the shape of the first
bytes as they pass. When the last byte lands the stream is placed in the
mailbox and the answer is `201` with the message id. `DELETE
/v1/uploads/{id}` lets go of an upload before then.

An attempt that stops short is judged by one rule. That is one whose
sender's link dropped, or whose bytes stopped coming. If it was the first
attempt and what the relay holds is at least the threshold, the partial is
kept for one resume, for sixty seconds from that moment and no longer.
Otherwise nothing is kept, and the upload, its file, its row and its
reservation go together. The sender's budget is then given back what the
relay never held, the size less what it had kept before that attempt. A kept partial stays
charged while it is kept. So the relay never holds less than a threshold's
worth of an upload that did not finish. A stream is placed by at most two
attempts on one id. A sender that trickles a byte at a time builds nothing
up. A budget is spent on what the relay holds or places and on nothing
else. The sender learns what the relay kept the way this wire tells it, by
the next attempt. One from zero on the same id is `409` with the kept
offset, from which it resumes once. It is `404` or `410` when the relay
has let the upload go, on which it opens anew. It is simply the fresh
attempt when the relay never saw the one that was lost. A resume after the
window is `410`, naming when the upload expired and saying to open again,
with the upload and its reservation gone. An upload nobody puts a byte to
within sixty seconds of its open goes the same way.

Bytes that stop coming end inside the window too. The attempt runs under the
relay's own stall deadline on the connection, sixty seconds, which no setting changes, and
moved on by every read that delivers bytes. So a transfer of any length
finishes while bytes keep arriving. A stalled one is cut and judged by the
rule above, its answer written under a fresh deadline of its own for anyone
still listening. The download of a placed stream is served under the same
deadline turned round, moved by every write that delivers bytes. So a
reader that stops is cut inside the window. A slow one is served to the
end rather than cut by the server's five-minute write timeout every five
minutes and left to ask by `Range`. The server's five-minute read and write
timeouts stand on every other route. A refusal before the body is read
closes the connection, and the answer is written before any of the body
is read. The standard library then reads up to 256 KiB of what was
declared before it closes, which is the one cost a refused attempt has.

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

### 2.3 A knock

A knock is the one message that reaches a mailbox from somebody its owner
has not admitted, and it reaches it only where the owner has said so on
their signed card. On the wire it is an ordinary sealed envelope, sign
then encrypt like every message, posted to a route of its own, `POST
/v1/mailbox/{fp}/knock`, and stored with the kind `knock`. It is a route
and not a field of the post because everything that can be judged without
the body is judged before it, and a kind inside the body would have the
relay read a whole post before learning it was a knock. So the route has a
cap of its own, `knock_max_bytes` plus 64 KiB of framing, and a body that
declares itself over it is refused `413` before a byte of it is read.

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
long as the row lives and no longer; an owner who would rather it did not
pushes a card that says no knocks. The allow list is
never read on this route, and the card is never read on the post route.
No card, a card that says no and a card that does not verify are one
refusal, `403 the
recipient does not take knocks`, since the state of somebody else's card
is not a stranger's to learn; the relay's own log says once a minute, under
either access log mode, that the card for the mailbox does not verify,
naming the mailbox and never the knocker.

Sealed inside a knock, where the relay reads none of it, are the knocker's
name, which is their own claim held to the name rule at both ends and
escaped wherever it is shown, and one line of text of at most 512 bytes
with no line break, tab or character a terminal would obey rather than
show. A knock opens a thread and answers nothing, carries no subject and no
attachment, and is never a stream: a manifest that says knock is refused.
