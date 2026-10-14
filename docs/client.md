# Using auu

This is the client in full. It covers what the README's quick start left out, and what lives where on disk. The commands here are the ones the Claude Code skills run. `skill/reference.md` lists every form and every `--json` shape.

## 1. Quick start for two people

This is the command line, for a person at a terminal, and it is also what
the skills run underneath.

Both people need a relay to talk through. Either one can host it, or a third
party can. The relay learns nothing either way. To run one locally:

*Listing 1a*
```
bin/auu-relay --listen :8080 --db relay.db --tls-mode off
```

That is plain HTTP, for a first try on one machine. A relay other people
reach serves TLS, which is its default, and refuses to start without a
bundle. [Running a relay](relay.md) says how.

### 1.1 Each person, once

*Listing 1.1a*
```
auu init --name bunty --relay http://localhost:8080
auu register
```

`init` prints an export line that looks like this:

*Listing 1.1b*
```
ccx2.<1664 characters of base64>.bunty
```

It is one token with no spaces, so it survives a double-click and pastes into
a command without quoting. A name is what goes after `--to`, so it is letters,
digits, dots, underscores and hyphens.

If somebody sent you an enrolment token for their relay instead, that whole
step is one command, which creates the identity and registers it:

*Listing 1.1c*
```
auu enrol --name bunty ccxt2.eyJpZCI6...
```

### 1.2 Exchange keys

Send your export line to your colleague over a channel you both already trust,
and confirm the fingerprint with them. Then each of you adds the other:

*Listing 1.2a*
```
auu peers add ccx2.<base64>.colleague-name
auu peers ls
```

If what you were given is a fingerprint, or the 16-character short id that
listings print, rather than a whole export line, ask the relay:

*Listing 1.2b*
```
auu lookup 4c1d9e2a7b0f3c58        # a fingerprint, a short id, or a peer's name
```

It prints the name they registered under, when, their keys and their export
line, and says whether they are already on your list. The relay is not a
trust anchor. That is a matter of checking with the person, and `lookup`
adds nobody.

The other way to find a colleague is the relay's listing of the people
who chose to be found there:

*Listing 1.2c*
```
auu listed                         # everyone on the relay whose card says list me, verified here
auu peers fetch bob                # add one, at a terminal, after reading the fingerprint
```

`listed` prints each identity's short id, the name on their card, their
keys and whether they are on your list already, and says which kind of
relay it is. Every entry was verified on your machine against the key
beside it. One the relay served that does not verify is left out and
counted.

`peers fetch` takes a name from that listing, or a short id or
fingerprint from anywhere, prints what `lookup` prints, and asks you —
`peers fetch` is yours, at a terminal, and the skills never run it. What
a name there rests on is who the relay admits: on a relay that invites by
token, an administrator let that identity in. On one that registers
anyone, a name proves nothing about who holds it, and the command says
so before it asks. The name offered as the local name is the owner's
own claim. Accept it or type another. Two people may claim one name,
and then the command says to use the short id.

Restrict your relay mailbox to the people on your list:

*Listing 1.2d*
```
auu allow push
```

Without this, any registered relay user can queue mail for you. Their messages
would land in quarantine rather than your inbox, but they would still occupy
space in your mailbox. The list goes to the relay signed by your key. The
relay checks the signature every time somebody posts to you, so nobody who
can edit its database can add themselves. An edited list refuses everyone
but you until you push again, and `auu inbox` tells you so. `auu allow show` prints
what each relay holds for you, verified with your own key. `auu allow clear`
opens the mailbox again.

Each of the three documents you push, the allow list, the card and the
channel directory, carries the time it was issued, and a relay refuses
one issued more than five minutes ahead of its own clock, with a
sentence that begins `by this relay's clock,` and names `issued`. A
document `auu` signs as it pushes never meets it: the push's request
carries this machine's time too, and a relay more than five minutes
apart from this machine refuses the request as stale before it reads
the document, so fix the clock. The document's refusal is met by a
document signed by hand. `auu channel push`, which sends the stored
directory under its stored issue time, meets the same check on this
machine first and exits 1 before any request is sent, so the relay's
refusal never comes to it.

The third document you can push is your card, and nothing is pushed until
you say so:

*Listing 1.2e*
```
auu card push --listed             # let the relay show your name and key to everyone it admits
auu card push --knocks             # say your mailbox takes knocks
auu card show                      # what each relay holds, verified with your own key
```

A card carries the name you chose at `auu init`, signed by your key, and
two words: whether the relay may list you, and whether your mailbox takes
knocks. Each flag defaults to what your last push said, so a bare
`auu card push` pushes the same card again, which is the repair `auu
inbox` names when a relay has lost it; `--listed=false` turns a word off
and `auu card clear` pushes a card that says neither, which is what having
no card means.

Saying you may be listed is saying you may be found by
every identity the relay admits, and what that is worth depends on the
relay: `auu relay show` says whether it invites by token or registers
anyone, and so does `auu lookup`. As with the allow list, a card edited
on the relay's host stops verifying, which the relay reads as `broken`
until you push again, and `auu inbox` tells you so.

The third way to reach somebody is to knock, and it is the only one that
does not need them to have added you first. It works where their card
says `knocks`:

*Listing 1.2f*
```
auu knock bob                      # one message to somebody who has not admitted you
auu knock 4c1d9e2a7b0f3c58 --text "alice from the Tuesday standup"
```

A knock is one sealed message from you — `auu knock` sends one and then
refuses, since they are a peer by then — of at most 512 bytes of text on
one line, carrying the name you call yourself. It goes to a route of its own on the
relay, which lets it past the recipient's allow list only because their
signed card says it may, and nothing else goes that way: a second knock
to the same person is refused, since they are on your list by then and
`auu send` is what writes to a peer. Before anything leaves, `knock`
prints what `lookup` prints, says what the relay's admission makes of a
name found there, and asks you twice — whether to knock, and what to call
them locally, with the name from their card offered and never taken by
itself. Like `peers fetch` it refuses without a terminal unless you pass
`--yes`, because it adds a peer, and the skills never run it. Once the
knock is posted it adds them to your peer list and, when this machine has
pushed an allow list to that relay, pushes it again so their reply
reaches your inbox rather than being refused.

On the other side a knock arrives in quarantine like any stranger's
message, listed as `knock` with the name they claim and their one line;
it is never left on the relay, whatever the channel's keep setting says.
`auu quarantine show` prints it whole, saying the name is their own
claim. `auu quarantine trust` is what accepts them: at a terminal it
offers their claimed name as the local name, saying it is their claim and
not a name you gave, and adds them once you accept it or type another.
With no terminal the claim is not offered at all, since the prompt would
take it with nobody there, and `peer-<short>` is offered instead. Then,
if your mailbox is restricted, it asks whether to push your allow list so
they can write to you.

#### Being introduced

A peer can tell you about somebody they hold, and you can take their word
for the key:

```
auu vouch xena --to rita           # victor tells rita he holds xena
auu introduce xena rita            # one each way: each is told about the other
auu peers add --vouched MESSAGE-ID # rita adds xena on victor's word, at a terminal
```

`auu vouch` signs a statement — *I hold this key on my peer list, under
this name, as of now* — and sends it to another peer as a message of its
own. Both must be on your list, and they must be two different people.
The name in it is yours for them. At the other end it is offered and
never taken. Signing it is an act of yours, so where the agent holds your
key it needs `auu unlock --send`.

At the other end the inbox lists it as `vouch`, with what it is for:
`vouches for "xena" 4c1d… (not on your list)`, or `(already your peer as
…)` once you hold them. `auu read` shows it whole. It counts only when
the person who sent it is on your list and its signature checks out under
the key you hold for them. A vouch from anybody else is held in
quarantine like any stranger's mail and adds nobody.

`auu peers add
--vouched` prints the fingerprint, whose word it is, and the sentence
*victor is on your list, so this is victor's word for the key*, asks, and
asks the local name with the voucher's name offered. It writes a comment
line above the entry, `# vouched for by victor (6b2e…) on 2026-10-01`,
which `auu peers rm` takes with the entry, marks the message read, and
offers to push your allow list as trusting a knock does. Like `peers
fetch` it refuses without a terminal unless you pass `--yes`, and the
skills never run it.

#### Asking a peer

When a stranger knocks, or a message from somebody you do not hold sits in
your quarantine, you can ask a peer whether they hold that key:

```
auu vouch --ask victor 4c1d9e2a7b0f3c58       # a short id from your quarantine, or a whole fingerprint
auu vouch answer on                            # let inbox and wait answer such questions by themselves
auu vouch answer show
```

The question reaches victor as a message of type `vouch-ask`, listed as
`asks whether you trust 4c1d… "xena"` when he holds that key, under his
name for it, or `(not on your list)` when he does not, and `auu read`
says which command answers it. He answers with `auu vouch xena --to
rita`, which reaches you as an introduction, or not at all: there is no
signed no, because a refusal would tell somebody he trusts something about
somebody he does not.

`auu vouch answer on` lets `auu inbox` and `auu wait` answer by themselves:
a question from a peer about a key on your list is answered with your
vouch, sent to them by the relay the question came through, and marked
read, with one line, `answered rita: you hold 4c1d… as "xena"`. Each
answer discloses one thing, that the key is on your list, with your name
for it and your signature, and only to a peer already on it. But nothing
limits how many a peer may ask, so a peer who asks about every key they
can see learns which of them you hold and what you call them. The
setting is for somebody content to tell their peers that. It is off unless
you turn it on, and the command says all of this when you do.

A question about a key you do not hold, or about you, is left for you. One
from somebody not on your list is in quarantine and never answered.
Serve's own rounds never answer one, though a handler of yours that runs
`auu inbox` is `auu inbox`. Signing the answer
originates as you, so where the agent holds your key and is unlocked only
to receive, the question is left unread and the line names `auu unlock
--send`.

#### Knocking with a vouch

A peer can give you a vouch to keep, for a knock to somebody who does not
know you:

```
auu vouch carol --to carol                         # bob, who holds carol, gives her one
auu knock alice --vouch bob                        # carol knocks on alice, carrying it
auu knock alice --vouch bob --vouch dave           # up to four
```

A vouch whose subject is you is kept when it arrives, under
`vouches/` by its voucher's fingerprint, and its inbox line says `bob
vouched for you; kept for your knocks`. A newer one from the same
voucher replaces it and an older one does not. `auu knock --vouch V`
reads the one kept from V, checks it still verifies and is still yours,
and carries it on the knock. It refuses a voucher you hold no vouch
from, and says how many to leave off when the knock would be over the
relay's knock size, which the relay tells every client.

At the other end the quarantine lists the knock with `vouched for by bob`
for each voucher the person holds whose vouch checks out, `and 2 you do
not know` for the rest, and says so of one that does not verify; `auu
quarantine trust` says whose word each is before it asks the local name.

Choosing what to carry is yours: a vouch tells the person you knock on
who vouches for you.

Trusting a vouch is trusting the voucher: somebody you hold can introduce
anybody to you, which is no more than they could do across a table. There
are no chains. A vouch counts only from somebody already on your list.
Once added, the entry is yours: the voucher changing their mind later
changes nothing here.

### 1.3 Send something

*Listing 1.3a*
```
auu send --to colleague --subject 'padding oracle?' --attach Decrypt.java \
  'Is this a genuine gap in the provider, or am I missing an entry point?'
```

Leave the text off at a terminal and `auu` opens your editor instead, the way
`git commit` does without `-m`. What you write above the `#` lines is the
message. The first line is the subject if you did not give one, and an empty
message sends nothing. A subject you did give is on a `# Subject:` line of
its own, which is there to be edited. Change it and the message goes out
with what you typed. Leave it and it goes out with what you gave. `--edit`
forces it, with any text you did give as the starting point. The editor is
`$AUU_EDITOR`, then `editor` in `config.json`,
then `$VISUAL`, then `$EDITOR`, then `vi`. The draft is kept at
`~/.auu/COMPOSE_MSG`, so a send that fails at the relay has not lost it.

What a message may say is prose. A subject is one line of at most 4096
bytes. Neither it nor the text nor a file's name may carry a character a
terminal would obey rather than show. Those are a control character, other
than a line break and a tab in the text, a format character such as a bidi
override, a private-use character, and a line or paragraph separator.
`auu send` refuses one before anything leaves, naming the character. A
receiver refuses the same when it opens a message, so what reaches a
listing or `auu read` is text. A record in the spool is held to the rule
again when it is read back. One that fails it, such as a file edited by
hand, is not shown. The
listing says once, naming the file, that it could not be read. Every print
escapes the rest all the same.

`--attach` repeats, and each file travels under its base name. There is no
directory, and no two names that are one file where case does not count.
`Report.txt` beside `report.txt`, or `Makefile` beside `makefile`, is
refused before anything leaves. The receiver may be on a disk that spells
them as one, macOS by default and Windows always, and a message that
cannot be written there is no use to anyone. For the same reason a name is
a file name on Windows too. It is not a device name such as `con`,
`nul.txt` or `com1.log`, which would open the device rather than a file
there. It holds no colon, which names a drive or a stream there. It holds
none of the six other characters Windows forbids in a file name
(`< > " | ? *`). It does not begin with a dot, which would hide it where it
is written. It does not end in a dot or a space, which Windows strips. It
is at most 200 bytes. The refusal names the rule and says it holds for
every receiver, since a sender cannot know where a message lands. The rule
is exactly what a receiver would change. `auu extract` writes every
attachment under a safe form of its name (see *Receive*). The sender's
rule is that the name is already that form, so an honest sender never
ships a name a receiver would write differently.

Above 64 KiB in all, the message goes as a stream. It is sealed to `outbox/`
first, then uploaded in one request per attempt, the whole of it or the rest
of it from where the relay's copy ends. An attempt that is interrupted is
tried again on the spot. `auu send --resume` finishes what a failed command
left. It asks the relay by an attempt from zero. It resumes once from the
partial the relay kept when it kept one, which it does for an attempt past
its threshold, within sixty seconds. Otherwise it opens anew for the same
sealed bytes. Nothing about the command changes. An attempt has no clock
over the whole exchange, but the relay holds it to a pace. An opened upload
waits ten seconds for its first attempt, and an attempt must bring the relay
a hunk of 64 KiB within ten seconds of its start and of each hunk before,
about 6.4 KiB a second, which is the least a link must sustain. A slower one
is cut by the relay as an attempt that stopped short. A relay that asks for
a wait, a `429` or a `503`, before the first attempt on an upload, for
longer than is left of its ten seconds less two, would let the upload go
before the attempt arrived. `auu` says so, `warning: the relay asked for a
wait of 20s before the first attempt, longer than the 10s an opened upload
waits; it is opened again after the wait`, lets the upload go, waits, and
opens it again once. The new open is charged as any open is, against the
hour's post bytes and the count of opens, and may itself be refused. A
second such wait in the same send lets that upload go too and stops the send
with the relay's words, the copy in the outbox for `auu send --resume`. A
relay also counts the uploads one sender opens in an hour, 64 by default,
each recipient's copy of a message to several one of them, and refuses an
open over it `429` `rate limited: upload opens`, with a `Retry-After` saying
when it takes another. The upload runs for as long as it keeps the relay's
pace. On its own side `auu` cuts it only when the relay takes no byte for
sixty seconds, with the sentence `the relay stopped taking the upload: no
byte was read for 60 seconds`. After either cut the next attempt asks where
the relay's copy ends. The download of a stream on the receiving side runs
under that sixty-second rule, `the relay stopped sending the stream: no byte
arrived for 60 seconds`, and resumes by range from where it stood. Every
other request to the relay is answered within two minutes or fails.
A relay, or a proxy or cache between, may not honour a range and answer
with the whole stream instead. That is a malformed answer naming the relay
and saying the range was not honoured. It is a transport failure. Nothing
is kept as damaged and nothing is acknowledged. The fetch from that relay
stops at the stream, and the stream and everything after it wait on the
relay for the next fetch. A fetch through a path that honours ranges
delivers them, so the remedy is a path with no proxy that strips `Range`.

A listing page whose ids do not rise from the cursor, each above the one
before, is a malformed answer naming the relay and the field `id`. It is
a transport failure too. Nothing of the page is acknowledged or kept, and
the fetch from that relay stops there.

A message to several goes to each recipient as a copy sealed for them,
and each copy names everybody it went to:

```
auu send --to bob --to carol --subject 'the release' 'out on Friday'
auu send --to bob,carol,dave 'the same, as one list'
```

`--to` repeats, and a value may be a list separated by commas. Each
recipient is a name, a fingerprint, `self` or a bang path. `--via` names
the relays for every recipient, so with it none may carry a path of its
own. A recipient named twice
is refused, and so is a list of more than thirty-two before anything else
is done. A list longer than the relay takes, which its health answer
says, sixteen by default, is refused naming the relay and the number,
before anything is sealed. A list you send to often can be saved as a
room; see [1.11](#111-rooms).

Every copy is sealed and written to `outbox/` before any is posted, then
each is posted in the order given. The command ends with one line per
recipient, `sent`, `not sent:` and the relay's words, or `waiting in the
outbox`, and exits 2 when any copy was not sent. A copy refused stays in
the outbox with the relay's words, and `auu send --resume` posts it
again. A relay that asks the sender to wait longer than a minute stops
the posting: that copy and the rest wait in the outbox, and the command
says how long the relay asked for. So does a relay that refuses this
machine itself, its certificate or its identity, with the advice a message
to one gets, and a copy that gets no answer at all. `auu read` of the
message you sent says who has it, who does
not yet, and which copies you gave up with `auu outbox drop`.

A message to several large enough
to become a stream goes as one stream to each recipient, every one sealed
to `outbox/` before the first upload, so `outbox/` holds the payload once
for each recipient until the uploads finish. A recipient by bang path
refuses the whole send, since a stream does not cross a relay. A stream
copy the relay refuses stays in the outbox with the relay's words, as an
envelope copy does, until `auu send --resume` finishes it or `auu outbox
drop ID PEER` gives it up, and the command names both.

Following up on a thread whose latest message is your own
to several needs `--to PEER`, one of its recipients, to say whom, or
`--all` to answer them all.

`auu outbox` lists what is sealed and waiting in `outbox/`, each with its
recipient, its relay and its size, and, for one a relay refused, the
relay's code and words, escaped. `auu outbox drop ID [PEER]` gives one up,
removing its record and its sealed file. The id may be four or more of its
first characters, and `PEER`, a peer's name or eight or more characters of
their fingerprint, says whose it is when one id has more than one thing
waiting. It does not ask first, as `auu rm` does not, since a message given
up can be sent again. A stream dropped part way leaves the relay to let its
part go when its window ends, ten seconds from the open when no attempt
started on it and sixty from the moment a partial was kept. Every command
that sends says, once, what waits: `warning: 1 unfinished message in the
outbox (1 stream); finish with 'auu send --resume' or give one up with
'auu outbox drop ID'`.

A note to yourself needs no peer at all:

*Listing 1.3b*
```
auu send --to self --subject 'remember' 'the milk'
```

Your own messages are never quarantined, and the relay lets you write to your
own mailbox whatever your allow list says. So a message to `self` is a queue
you can read from any machine holding your identity. Nobody can be named
`self`. The word is reserved for this.

That prints a message id and a thread id. To block until the answer arrives:

*Listing 1.3c*
```
auu wait --thread THREAD-ID --timeout 30m
```

On an expert, a thread id names the conversation of the peer who opened
it and nobody else's. Another peer can name the same id with `auu send
--thread`, and `auu serve` leaves that message unanswered.

Each poll asks the relay to hold the listing open for the interval, so the
reply arrives when it is sent rather than at the next poll. A relay over
its cap on holds answers at once instead, and the wait sleeps the interval,
which it cannot tell and does not need to. The timeout is the wait's own.
Every poll runs under it, so a relay that accepts a connection and never
answers is cut off when the time is up, and the exit is 3 either way. A
poll that fails for a reason waiting may outlast is said on stderr and
tried again at the next interval. Such reasons are the relay unreachable,
the connection lost, or the relay failing. A refusal no interval would
change, such as a certificate the relay will not accept, ends the wait at
once with exit 2.

### 1.4 Channels

A mailbox can have named sub-mailboxes, called channels, that you define and
a sender chooses between, such as `bug reports`, `cfp`, `default`. Each has a
description and, if you like, a period in which it takes mail. Until you
define any, your mailbox has the one channel, `default`, and nothing
changes.

*Listing 1.4a*
```
auu channel ls [PEER] [--json]
auu channel create NAME [--description TEXT] [--not-before T] [--not-after T]
                    [--max-bytes N|none] [--no-streams|--streams] [--no-forwards|--forwards]
auu channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]
                    [--max-bytes N|none] [--no-streams|--streams] [--no-forwards|--forwards]
auu channel close NAME [--at T]
auu channel delete NAME
auu channel keep NAME on|off
auu channel push
auu channel pull
```

Times are RFC 3339 with a zone, or a day such as `2026-10-01`, taken as
midnight where you are. A description is one line. Line breaks and tabs in
what you type are folded to a space. Names are at most 64 bytes, descriptions
1024, and a directory holds at most 64 channels. A name has no leading or
trailing space or dot, no `/`, `\` or `:`, none of `< > " | ? *`, no
Windows device name as its stem (`CON`, `NUL`, `COM1`), and no control or
format character. Case counts, so `Bugs` and `bugs` are two channels. The
Windows rules are there because a name is a directory on an expert host,
which may be one.

The first `create` writes `default` beside the new channel, so creating a
channel never takes the default away. `auu channel delete default` does,
after which a sender who names no channel is refused and told what there is.
`delete` deletes. The relay never refuses because mail is queued under the
name. What was queued still arrives with the next `auu inbox`, filed
under that name, which says the channel is no longer in your directory.
`close` sets the period's end to now, or to `--at`, and refuses a time before
the channel opens. The channel stays listed, marked `closed`, and nothing
queued is touched. Deleting the last channel warns that nobody can post to
you.

The directory lives in `channels.json` in your home. It is signed by your
identity key and pushed to every relay you are registered on, or the one
`--relay` names, one line per relay: `work: directory pushed (3 channels)`.
A relay that refuses or cannot be reached is named, and the command exits 2
with the file already written. `auu channel push` catches that relay up
later, under the same signature, and so under the stored issue time.
The push runs the relay's check on this machine before anything is
sent, and a directory that fails it is refused with exit 1 and advice
that depends on the refusal. A stored issue time now more than five
minutes ahead of this machine's clock, which has gone back since, or
one outside the range a relay takes, gives the advice to create, update
or close a channel, which issues the directory anew at this machine's
now. A relay that already holds the stored directory then answers
`409`, since the new one is issued earlier, unless what it holds was
issued more than five minutes ahead of the relay's clock, which is no
bar. A channel whose `not_before` or `not_after` lies outside the years
0000 to 9999 gives the advice to update that channel's bound. Two
machines of one identity are kept from writing over each other. Every
edit first asks each relay what it holds. A relay holding a directory
issued later than this machine's stops the edit with `work holds a
directory issued T, newer than this machine's; run 'auu channel pull
--relay work' to take it first`. `pull` takes that directory into the
local file, and the edit goes through after. A directory is held to 512
KiB and an allow list to 128 KiB — the bytes the owner signed, checked
before either is sent and again by the relay before the signature — and
the request that carries one to 1 MiB, the relay's cap on the two routes.
A full directory of 64 channels at every limit, every rule set, is about
430 KB signed and 574 KB on the wire, and a full allow list 67 KB and 90 KB, so what `auu`
signs always fits with room to spare. A document that does not fit (`the
directory is N bytes; at most 524288, so send it compact; nothing was
sent`) is one another tool indented, and the answer is in the sentence.

Sending to a channel is `--channel NAME` on `send` and on `reply`. Without
it a message goes to the recipient's `default`. A reply goes to the
sender's `default` too, since a channel is the receiver's sorting, not a
thread. `sent/` records the channel. The relay refuses a name the recipient
has not published. `auu send` then fetches their directory, verifies it
against the key you hold, and says `bob has no channel "x"; their channels
are:` with one line each. When they have none it says `bob's mailbox has
the one channel, default; drop --channel`. When you named nothing and they
have removed `default`, it says `bob has removed their default channel;
choose one with --channel:` and the list. A channel outside its period is refused with
the relay's own sentence, `channel "cfp" is not open: opens T` or `closed
T` with T in UTC, followed by the same time in your zone, `(T here)`,
when your zone reads it otherwise. Each is exit 2, as a refused allow list is,
and nothing was queued.

A channel may also say what it takes, under the relay's own caps and never
looser than them. `--max-bytes N` is the largest message it takes, in
bytes on the wire: an envelope, or a sealed stream with its manifest,
whichever way the message comes. It is a whole number from 1, written in
digits, and `none` clears it, leaving the relay's own cap. `--no-streams`
refuses every stream to the channel and `--streams` takes them again;
`--no-forwards` refuses every message that comes by way of another relay
and `--forwards` takes them again. A channel with any of the three is a
rule the relay enforces at every post, stream and delivery, out of the
directory it verifies then. A directory with a rule is version 2, which
only a v0.18.0 relay or later takes, so before any push of one `auu` asks
each selected relay's health: a relay at wire level 1 refuses the edit
with `relay work is at wire level 1 and cannot hold a channel rule;
update it, or drop --max-bytes, --no-streams and --no-forwards` and exit
1, a relay at level 2 or later that does not say the largest
`max_bytes` a channel on it may name refuses it with exit 1 and the
advice to update it, a relay that cannot be asked refuses it with exit
2, naming the relay each time, and a `--max-bytes` over the most a relay
takes is refused naming the relay and its number, all before anything is
pushed. That
promises only that no push starts on a relay known not to take it: the
pushes go relay by relay, so one relay can still take the directory and
the next fail, which the per-relay lines say and `auu channel ls` shows.
`auu channel push` mends a relay that failed; one that answered with a
newer directory is mended by `auu channel pull --relay` from it and the
edit made again. The first rule you set says once that peers on v0.17.0
or earlier will say your directory `does not verify against the key you
hold; do not trust it` until they update `auu`: that is their old build
meeting a newer document, not a key problem, and updating is the remedy
on their side. Their `auu watch` on you stops, `auu channel ls` refuses
it, and when a send of theirs is refused the hint says the same instead
of naming your channels, though they still send to your channels. It
also says that this home cannot go back below v0.18.0 without dropping
the rule first. A directory with no rule stays version 1,
exactly as before.

A sender refused by a channel's rule sees the relay's sentence, `channel
"logs" takes no streams` or `channel "logs" takes at most N bytes on the
wire; this message is M`, with exit 2, and the outbox keeps or drops the
sealed copy as it does for a closed channel. A message sent by way of
another relay to a channel that takes none of them comes back in `auu
queue` as refused, with `channel "x" takes no mail by way of another
relay` at the end of the sentence. The list `auu send` prints for an
unknown channel gives each channel's rules after its state.

`auu channel keep NAME off` says that mail fetched from that channel is
acknowledged away on the relay at the fetch. `on`, which is the
default for every channel, leaves it queued there until you remove it with
[`auu rm`](#15-receive). It is this machine's own policy. Nothing is signed,
nothing is pushed, no relay is told, and the command works with the keys
locked. It lives in `channel-settings.json` in your home, so a copy of the
home takes it to a second machine. `auu channel pull` never touches it. The
name need not be a channel your directory still holds, since mail queued
under a deleted channel still arrives. A file that will not read, that
gives a channel no `keep` or that names a channel twice is refused by name
with exit 5, and nothing is fetched under a guess.

`auu channel ls` prints your channels: name, description, period,
`open`, `opens T` or `closed T`, `RULE`, which is `-` or the channel's
rules joined with `, ` (`≤ 64 KiB, no streams, no forwards`), how many
messages wait under each, and `KEEP`, `on` or `off`. Then, per relay, it says whether it holds this
directory, an older one (`run 'auu channel push'`), a newer one from
another machine, or none. `auu channel ls PEER` prints a peer's channels
the same way, without counts, fetched from the relay and verified against
the key you hold for them. Somebody not on your peer list is a usage error,
since the relay is not a trust anchor. A directory that does not verify is
refused with exit 2 and one of three sentences, by where it failed: `the
directory work served for alice does not verify against the key you hold;
do not trust it` for a signature or an owner that is not theirs, `the
directory work served for alice is one this build cannot read; update
auu` for a version newer than this build reads, and `the directory alice
signed is malformed; tell them` for anything else they signed. The hint
`auu send` prints and `auu watch` say the same three; a watch drops that
peer, says so once, and runs on for the others. `--json` gives the
structure, with `open` as a boolean, `why` as the sentence, and
`max_bytes`, `no_streams` and `no_forwards` on a channel that has them.

The relay verifies your directory against your registered key every time
anybody posts to you, not only when you push it. So a directory edited on
the relay's host stops routing rather than routing something you did not
publish: the mailbox closes. Every name, `default` and your own note to
yourself included, is refused with `no such channel`, and `auu inbox` and
`auu wait` tell you once a run — `your channel directory on work does not
verify, so every post to you is refused there; run auu channel push, and
if you did not change it, tell the relay's operator`. It closes rather
than falling back to `default`, because falling back would open a channel
your own directory may have removed or closed. A fresh `auu channel push`
is the whole repair, as it is for the allow list and the card.

### 1.5 Receive

*Listing 1.5a*
```
auu inbox                    # fetch from the relay and list
auu read MESSAGE-ID          # read one
auu extract MESSAGE-ID       # save its attachments
auu rm MESSAGE-ID            # remove it from the relay and from here
auu reply MESSAGE-ID 'It is missing. Open an issue against home-java.'
auu queue                    # mail a relay is still carrying onward
auu damaged ls               # what the fetch kept because it could not open it
auu damaged reopen --all     # open what needed a newer auu, once auu is updated
```

**Mail that came by another relay** says so. `auu read` prints a `via` line
naming the relays it crossed, nearest the sender first, and `auu reply` goes
back along that address reversed without being told. So answering somebody
on another relay is the same command as answering anybody. A message posted
to your own relay has no `via` and no line, which is most mail.

The reversal can fail, and it is worth knowing why. Each name in `via` is
what that hop calls the hop before it. A reply's address is resolved against
the list of relays a relay *dials*. Operators are meant to use one name in
both places and a relay complains at its start when they do not, but nothing
can enforce it and a one-way peering is legitimate. Where the two disagree
the first hop refuses your reply, naming a relay you never typed, and `auu`
says the message cannot go back the way it came and offers `--via NAME` or
`--relay NAME` to answer anyway.

**What is still on its way out** is `auu queue`: mail you addressed to
somebody on another relay which your relay has taken and not yet handed over.
Each row says which neighbour it is going to, what is left of the address,
how many times it has been tried, when it will be tried again and when your
relay gives up.

A row that failed says why. Its code is `refused` — some relay along the way
would not take it — or `gave-up`, meaning a relay stopped trying a neighbour
that was not answering: your own relay, if the row never left it, or a relay
further along, which tells the one behind it and so on back to you. Beside it is
the sentence the relay that actually failed gave, with each hop's name in front
of it as the news came back: `bar: baz: no such mailbox` is `baz` refusing it, reported to you
through `bar`, each named as the relay in front of it names it. So you learn
which relay along the way said no and what it said, rather than guessing. One
sentence means the address itself was the trouble: `already carried` is a
relay that had this message already, because the path you gave led back to a
relay it had passed through, and it was stopped there rather than delivered.
Rarely it is instead a relay that failed the message a day or more before your
relay asked again, and has forgotten why.
A very long chain eventually fills the sentence, and then it is the front that
is dropped, marked with `…`, because the reason it failed is worth more than
the list of names. The first name you lose is the one on the line above
it anyway. `auu inbox` prints one line while anything
is waiting and says nothing when nothing is.

`auu extract` writes each attachment under `--out` (the working directory
by default) as a new file, and never depends on the sender for the name.
Whatever the sender called it, the file is written under a safe form of
the name, and made unique at the write. The safe form is the base name
alone, with any character a terminal would obey or Windows forbids made
`_`. A trailing dot or space is trimmed. A leading dot is made `_`, so
nothing hides in your directory. A Windows device name is prefixed with
`_`. The name is cut to 200 bytes, and is `attachment` when nothing is
left. A name that already stands there, whatever it is, is left alone,
and the file is written beside it as `x-2.txt`, `x-3.txt`. So what your
disk folds, such as case on macOS and Windows, is settled by the disk's
own answer and nothing is overwritten. A directory that already holds a
thousand names like it is refused with the count, and `--out` somewhere
else is the answer.

The line that reports each file says the sender's name where it differs
from what was written. The file is made and the spooled bytes are read by
their handle, not their name. An attachment that turns out not to be a
regular file is refused with a sentence saying what was found, and nothing
is written. A device the name reaches on this platform, a pipe or a link
somebody planted in the spool are all refused that way. The bytes are
written first to a hidden temporary of `auu`'s own name in the same
directory, and checked against the message's size and digest there. The
attachment's name is taken only then, by linking the temporary to it, so
the name appears with the whole verified file or not at all. An extract
killed part way leaves a `.auu-extract-*` file to delete and nothing under
the name. On a filesystem that refuses hard links, such as FAT or exFAT on
a stick or some network shares, the name is taken by an exclusive create
and the verified temporary is copied into it. There a kill mid-copy can
leave a partial file under the name, and the next extract writes beside it
as `x-2.txt`. An extract is all or nothing. When one attachment fails, the
files this extract already wrote are removed and nothing else is, so a
retry writes the plain names. A file somebody replaced meanwhile under one
of those names, or one that could not be removed, is left and named in the
error.

A message to several says so. The inbox listing marks it `(to N)`, and
`auu read` prints a `to:` line naming everybody it went to: the name your
peer list has for each, the short fingerprint for one it does not know,
and `you`. `--json` carries `recipients`, each `fingerprint` and `name`.
`auu reply` answers the sender alone. `auu reply --all` answers the sender
and every other recipient, as a message to several of its own, or as an
ordinary reply when that is one person. Every one of them must be on your
peer list, since a message is sealed to a key you hold: when one is not,
the whole reply is refused before anything is sealed, naming them, and the
two things to do are to ask the sender to vouch for them or to add them
with `auu peers add`. It goes through the relay the message came by, so a
recipient who is not registered there is a copy left in the outbox, and
the sentence says to reach them with a new message to `'RELAY!NAME'`, or
to a room that holds them. It takes no `--to` or `--via`, since a reply
goes back the way the message came.

A copy of a message you already hold that arrives
again, which a sender's `--resume` after a lost answer can post, is
acknowledged and not delivered twice. Where the channel keeps its mail and
the relay still has your copy, the fetch says `N already held`. Where it
does not, the second copy is met as any message the relay serves again is,
and nothing is said. A copy that arrives again after you removed the first
with `auu rm`, from the relay and from here, is new mail to this machine,
since nothing here remembers mail removed that way, and it is delivered
again.

A thread id works there too. `auu reply THREAD-ID` answers whatever is
latest on the thread, including your own last message. In that case it is a
follow-up to the person you sent it to. Latest is by when the message
arrived on this machine, by this machine's clock, and then by the relay's
own numbering, with the relay's time breaking a tie. The inbox lists in the
same order. It is never by the time stamped inside it, which is the
sender's word, nor by the relay's time alone, which is the relay's. `auu
read` shows the sender's stamp as `sent:`, labelled the sender's clock,
beside `received:`, the relay's. `--json` carries all three, as `time`,
`received` and `arrived`. Mail an earlier release kept here counts as
arriving when the relay received it, unless that time is one this program
cannot write back or is more than five minutes ahead of this machine's
clock, which no honest relay sends; then it counts from when its file was
last written, held to the same two, and otherwise from now, and auu warns
once per command, naming which it took, until the record is next saved.
A message stamped more than forty-two minutes in the future is refused
when it is opened. The bound is the chain of clocks a message
may cross: the sender within five minutes of its relay, each relay within a
minute of the next, the last within five minutes of this machine, which
over the protocol's thirty-two hops between relays is forty-two minutes. An
honest message's stamp is closer: eleven minutes over one hop, eighteen
over eight, a relay's default `courier.max_hops`. Message and thread ids
are the same shape, and either may be shortened to a unique prefix.

A reply carries the thread's subject unless you give it one of its own, with
`--subject` or by editing the `# Subject:` line in the editor. The thread is
still the thread. `auu read` then prints the thread's subject and the
reply's own indented beneath it. `--json` adds `thread_subject` beside
`subject`, which is always the message's own.

A fetch reads the mailbox in pages of up to 200 messages, and a page is
also bounded in bytes by the relay. It ends before an envelope that
would take it past the relay's `max_bytes`, or past 64 MiB on a relay of
this release whatever its `max_bytes`, admitting the first whatever its
size. So a page's envelopes never exceed that unless the first alone
does. A relay of this release stores no message over 64 MiB inline, and
`auu` sends at most 16 MiB inline. `auu` learns the relay's `max_bytes`
from its health answer the first time it lists, and holds a page to
twice that plus 64 KiB, up to 128 MiB and 64 KiB whatever the relay
says. A relay that does not say its `max_bytes` is one from before this
version and is refused by name.

A fetch takes what the relay held for you when it began. The first page
gives the relay's highest number, and mail listed past it waits for the
next fetch: the cursor is saved at the last message taken and nothing is
said, and `auu inbox --json` sets `more` true on that relay's entry in
`relays` and on `fetch`. A fetch also asks one relay for at most 64 pages,
at most 12,800 messages at 200 a page, which bounds a relay whose highest
number does not hold. At that cap it says once

    work: this fetch took the 64 pages it asks at most; the rest waits for the next fetch

sets `more` the same way, and exits 0. The next `auu inbox` takes the rest
from the saved cursor, and `auu watch` and `auu serve` take it on their
next round. A fetch from the relay's lowest number after a reset (*When the
relay's numbering restarts*) runs to the end of what the relay lists and is
held to the 64 pages alone. One cut there is not finished, and the account
of what was left on the relay waits for a fetch that reaches the end. The
check before such a fetch, which lists the relay's mail to match it against
what this machine holds, asks at most 64 pages too; a relay that lists more
fails the fetch, with nothing changed here; the next `auu inbox` asks
again, while `auu watch` and `auu wait` take it for a relay that will not
answer and end, exit 3. `auu wait` fetches at every poll and meets the rest
there. A page holds no more messages than the fetch asked for: one listing
more is refused as a malformed answer before any of them is taken. A
stream's refusal that the client waits out is read to at most 64 KiB, as
every stream answer is, and one longer is refused the same way, the
connection given up.

A page over the hold is asked for again, with half as many messages each
time, down to one, when the hold is already at 128 MiB and 64 KiB: at
most seven more asks from 200. That is how `auu` reads a relay not yet
upgraded, which fills a page to its whole `max_bytes`. A page still over
the hold is refused as a malformed answer naming the hold, and nothing
of it is acknowledged or kept. So a single message over the hold, stored
before the relay's upgrade, on a relay not yet upgraded, or under a
larger `max_bytes` than the relay says now, is refused whatever the
page, and every fetch from that relay stops at it until the message goes
or the cursor is moved past it. While the message is still after the
cursor, the fetch is a transport failure on that relay alone, and your
other relays are fetched as usual.

The recovery that ends it is the relay's operator's:
`auu-admin mailboxes purge FP` discards every message queued for you
there, not that one alone. `auu cursor reset --relay NAME --to ID`, with
ID that message's relay id, which `auu cursor show` gives as the relay's
lowest number when nothing before it is still there, steps past it in
the meantime. It lets the mail after the message through and loses that
message alone, at a cost: the message stays on the relay and is counted
there, so once the cursor is past it every fetch from that relay ends
at exit 5, saying a message is waiting before the cursor, until the
operator removes it. That is no longer a transport failure: in a home
with several relays `auu inbox` then stops at that relay and does not
fetch the ones after it, and `auu watch` stops watching that relay, and
ends when it is the only one. That exit's sentence advises
`auu cursor reset --relay NAME`, from the beginning, which leads
straight back to the message.

Mail from a sender who is not on your peer list is held back:

*Listing 1.5b*
```
auu quarantine ls
auu quarantine show MESSAGE-ID
auu quarantine trust MESSAGE-ID    # adds them to your peer list
```

A knock is listed there as `knock`, with the name its sender claims and
their one line, both escaped before they reach your terminal. It is never
left on the relay, so it holds no room in your mailbox. `trust` on a
knock offers the claimed name as the local name and, when this machine
has pushed an allow list to that relay, asks whether to push it again so
they can reply. Answering no prints the `auu allow push` to run later.

`trust` asks the local name first, and refuses a name another peer or a
room already has, a name the export line's rule refuses, or a peer list
it cannot read, before anything is fetched or acknowledged. For a stream
it then fetches the manifest again and holds it to the quarantined record
before asking for any of the payload. A
different sender, message id or channel is refused, naming the message by
the start of its id, with `the stream on the relay is not the one that
was quarantined; nothing was delivered and the record is as it was`. The
same stream whose manifest disagrees with the size the relay listed when
it was quarantined is done with as the fetch does it: kept under
`damaged/` with both numbers and acknowledged, taken out of the
quarantine, and the command exits 0 with `its manifest says the stream is
N bytes on the wire and the relay listed M; it was settled as damaged and
acknowledged, and nobody was added`, as the payload that will not open
below is settled. That clears such a stream from a
stranger that a build from v0.14.0 to v0.17.0 quarantined. A record made
by a build before v0.14.0 kept no size, and for it only the size goes
unchecked. The same stream whose manifest verifies but whose payload will
not open, because it does not decrypt or fails its digest, or whose relay
says the range asked for lies beyond its stored file, is settled as the
fetch settles a peer's: its manifest chunk kept under
`damaged/` with the fetch's warning, the stream acknowledged and taken
out of the quarantine, and the command exits 0 with `its payload will not
open; it was settled as damaged and acknowledged, and nobody was added`;
an earlier build called it a transport failure and downloaded the whole
payload again at every trust. A relay that has dropped its copy, and
answers that the body is gone, is not the sender's doing and is not
settled: the command exits 2 with `its body is no longer on the relay;
ask the sender to send it again`, nothing is kept or acknowledged, and
the message stays in the quarantine. A connection that drops while the
payload comes is still a transport failure, exit 2, and the message stays
in the quarantine to be trusted again. The sender is added to your peer list once the message is
delivered and, where its channel does not keep it on the relay,
acknowledged, so a trust refused for any of these adds nobody and leaves
the list as it was: a transport failure, a body no longer on the relay, a
stream on the relay that is not the one quarantined, a size that
disagrees, a payload that will not open, or a name already taken. To
trust the sender anyway, add them with `auu peers add` and their export
line, `ccx2.<base64>.name`, as for any colleague. A stream whose signed
manifest disagrees with the size the relay lists is not quarantined: the
fetch keeps it under `damaged/` with both numbers and acknowledges it,
whoever sent it. The exception is a
stream that waits for a newer auu, which is recorded before its size is
checked; from a stranger, `trust` checks it once a build knows its
section, and from a peer the newer build's fetch does.

*Listing 1.5c*
```
auu rm MESSAGE-ID...               # from the relay and from here
auu rm MESSAGE-ID --remote-only    # from the relay; keep the local copy
auu rm MESSAGE-ID --local-only     # from here; leave the relay's copy
```

A message you have fetched is still on the relay. A channel keeps its mail
by default, which is what lets a second machine of yours read the same mail,
and `auu rm` is what removes it. `auu inbox` marks such a message ` on relay`
at the end of its line. `--json` says `on_relay`. `auu read` says
`relay: kept` or `relay: removed`. After the listing comes one line per
relay, `work: 12 message(s) on the relay; auu rm removes them`. A
quarantined stream is marked ` body not fetched` instead. Its body was
deliberately left on the relay rather than downloaded for a stranger. That
stays true of this machine whether or not the relay still has it.
`auu quarantine trust` says `its body is no longer on the relay; ask the
sender to send it again` when it has gone. The marks are checked against
the relay on every fetch, so mail another machine of yours removed stops
being marked here. A check that cannot be made says so once and changes
nothing. `auu channel keep NAME off` is the other choice for one
channel: the fetch acknowledges the message away.
Kept mail counts against the relay's per-mailbox limits, so a sender whose
message is refused is told the recipient must run `auu rm`.

`auu rm` takes ids as `auu read` does, a unique prefix being enough. It
removes each from the relay first and then from here, in that order, so a
relay that cannot be reached leaves the local copy for a second run. The
ids already done are printed, and the command exits 2 naming the relay.
`--remote-only` keeps the local copy and only stops it claiming to be on
the relay. `--local-only` frees the disk here and leaves the relay's copy,
which this machine will not fetch again. It remembers the id in
`relays/<name>/left-behind`, so a later fetch does not mistake it for mail
the cursor has skipped. A sent message was never in your mailbox, so `rm`
removes it here, and `--remote-only` on one is a usage error that says so.
`--json` gives `{id, relay, removed_relay, removed_local}` per id.
`--local-only` needs no key and works with the agent locked. Anything that
speaks to a relay does not.

The fetch is the whole mailbox, every channel at once, and a message is filed
under the channel it was sealed for. `auu inbox` prints the channel after the
subject when it is not `default` (`in "bug reports"`). `--channel NAME`
narrows the listing without narrowing the fetch. `auu read` prints
`channel:` always, and `--json` carries `channel` on every message. Mail
queued under a channel you have since deleted still arrives, filed under that
name. The summary says `N message(s) arrived for channels no longer in
your directory: "bug reports"`. Quarantine files the same way. A message
and a stream's manifest are read strictly. So one that carries a field this
build does not know is refused as malformed and kept under `damaged/`. That
is what a peer running something other than this `auu` looks like from here.

*Compatibility.* v0.15.0 is the floor. Everything you use, your `auu`,
your peers' and the relays, goes to v0.15.0 or later once, together, and
after that versions may differ. v0.14.0 and before are not supported.
v0.18.0, v0.17.0, v0.16.0 and v0.15.0 mix in any order, as sender,
relay and recipient alike. v0.17.0 and v0.18.0 send and relay what
v0.16.0 does, and a message to a room is a message to several on the
wire, so v0.16.0 in the table stands for v0.17.0 and v0.18.0 as well:

| Sender | Relay | Recipient | What happens |
| --- | --- | --- | --- |
| v0.16.0 | v0.16.0 | v0.16.0 | Each copy of a message to several is delivered and read, and `auu reply --all` answers everyone. |
| v0.16.0 | v0.16.0 | v0.15.0 | A message to several is read as a plain message from the sender; `--json` names `recipients` in `ignored_sections`, and `auu reply` reaches the sender alone. |
| v0.16.0 | v0.15.0 | any | The relay takes every copy. A plain post carries nothing for it to read, and it ignores the count on a stream's open and on a copy sent on by bang path; its health answer says no `max-recipients`, so the sender holds itself to 32, the protocol's ceiling. |
| v0.15.0 | any | any | Each message goes to one recipient, as it always has. |

Nothing is kept as `newer` or `malformed` in any row. The break with
v0.14.0 runs one way and is unchanged: v0.14.0 reads what v0.15.0 and
later send, except a large message to several, and v0.15.0 and later
refuse a message v0.14.0 sealed, other than a stream, as malformed and
keep it under `damaged/`. The release notes give the order to upgrade
in from v0.14.0 and what each release changed:
[`docs/releases/v0.15.0.md`](releases/v0.15.0.md),
[`docs/releases/v0.16.0.md`](releases/v0.16.0.md),
[`docs/releases/v0.17.0.md`](releases/v0.17.0.md) and
[`docs/releases/v0.18.0.md`](releases/v0.18.0.md), which takes v0.14.0
straight to v0.18.0 and says what a v0.18.0 party and an earlier one
meet.

One home runs one `auu`. A newer `auu` fetching mail for an older `auu
serve` on the same home is two versions on one home, which the floor does
not cover. A thread a v0.17.0 serve tried takes no opener from mail a
v0.18.0 `auu` fetched, since that mail arrived after the upgrade as far as
the ledger can tell. Unless another of its messages names an opener, it is
nobody's: serve answers no message on it and says so once each run (see
[the serve guide](serve.md)).

From v0.15.0 on, a
newer build adds what it adds through sections in messages and in what
relays and clients send each other, and through refusal codes. An older
build ignores what it may and refuses by
name what it must, and never reads a newer message with a part dropped.
A relay's `wire_level` says what it can do.

*From a newer build.* A newer `auu` may add a section to a message: a part
with a name, which this build may not know. A section it does not know and
was not told it must is passed over, and the message is read as usual. The
section is kept with the message as it came, up to 16 KiB, so a later `auu`
on this machine can read it, and `--json` names it in `ignored_sections`. A
larger one is not kept, and `dropped_sections` counts it. A section is
known only where this build reads it, so `recipient-count`, which it
reads on a request alone, and `max-recipients` and `channel-max-bytes`,
which it reads on an answer alone, are each held on a message as an unknown one is: kept up to
16 KiB, named in `ignored_sections`, and counted in `dropped_sections`
over it. A message an earlier release kept with such a section over 16
KiB still loads; the cap holds what is fetched from now on. A section the
sender marked critical that this build does not read on a message, one it
does not know at all or one it knows only on another path, as either of
those two, is one it must not read past:

- A message is kept under `damaged/` with the cause `newer` and the
  section's name, and acknowledged. The warning names the sender, your
  peer's name or "an unknown sender" and the start of the fingerprint, and
  says to update `auu` and open it with `auu damaged reopen RELAY ID`. It
  never says to ask the sender to send it again. `auu inbox` says every
  time how many are kept so, and names `auu damaged reopen --all`.
- A stream waits on the relay, unacknowledged, with a record of it in your
  inbox, or in the quarantine if the sender is not your peer, marked
  `needs a newer auu` with the section's name. `auu read` and `auu reply`
  say so and show nothing of it, the quarantine's `show` and `trust` do the
  same, and `auu inbox` says every time how many wait. Once `auu` is updated
  to a build that knows the section, the next fetch fetches the stream whole
  from the relay into the box it waited in, and a stranger's stream waits on
  in the quarantine as any stranger's does. If the relay no longer holds it
  by then, the fetch says so once.

*What the fetch kept.* `auu damaged ls` lists what is under `damaged/`,
oldest first: the relay, the relay's id for the message, when it was
received, its size on this disk and its cause. It needs no key. The
directory holds at most 64 MiB and at most 1,024 messages, and the oldest
go first to make room, by bytes or by count, so a relay that hands over
small messages that do not open cannot fill it under the bytes. A message
whose keep was cut off before its record was written is listed with
`no record:` for its cause, and one beside a record that does not read
with `unreadable record:` and why. For both, the time is the file's own.
Both count against the budget and are evicted as the rest are. A file
there that is not a kept message is named on stderr, `warning: PATH is not
a kept message and is not listed`, and left alone; it is not counted. When
any were kept as `newer`, the listing ends with how many and `auu damaged
reopen --all`. `--json` gives a list of `relay`, `id`, `received`,
`size`, `cause` and `section`. `cause` is empty for a keep with no record
or a record that does not read. `section` is there for a message kept as
`newer` alone.

`auu damaged reopen RELAY ID` opens one kept message again with this `auu`,
and `--all` opens every one kept as `newer`. `newer` is the only cause it
opens. A message that did not decrypt or was malformed cannot be opened by
any `auu`, and one kept as misfiled was refused by a check that would
refuse it again. Reopen refuses a message of any other cause by name, at
exit 1:

    work 7 was kept with the cause "malformed", which is never reopened; only a message kept as needing a newer auu is

Bytes kept with no record, or beside a record that does not read, are
refused the same way.

Reopening runs the fetch's own checks on the kept bytes, with the relay and
received time its record names. What opens is filed where the fetch would
have filed it: the inbox for a peer, the quarantine for anybody else. Its
two files under `damaged/` are then removed. Each message is one line:

    work 41: opened and filed in the inbox
    work 42: already held, so its kept copy is removed
    work 43: still needs a newer auu (section "x-poll") and is left where it is
    work 44: its id is held from another sender, so it is left where it is
    work 45: it was filed under "a" and sealed for "b", and is left where it is

Already held is a copy of a message you have, from the same sender, kept
twice. What is left stays under `damaged/` as it was, and the command
still exits 0. The record of a message kept as `newer` says what the
relay's listing said of it: the kind and the channel it was listed under.
A record an earlier release wrote does not. The checks against the listing
cannot run for it, and its line ends `; its record does not say the kind
it was listed under or the channel it was listed under, so that check
could not run`. The envelope's own channel is still checked.

Reopen fetches and acknowledges nothing. The fetch acknowledged each
message when it kept it, so a filed message is not marked ` on relay`. A
message from a relay since removed from this home still opens. Reopen
needs the key as a fetch does, unlocked to receive at least. Locked, it
exits 4. It takes the relay's `fetch.lock`, so it waits for a fetch from
that relay to finish, up to a minute, and then exits 2 saying so. Under
`--all`, what was filed before the key locked, or before a lock it waited
for ran out, stays filed, and stderr says how many. When it files
anything, it keeps a vouch, and with `auu vouch answer on` set it answers
a peer's question, as after a fetch. That answer is the one thing reopen
can send. `--json` gives a list of `relay`,
`id`, `outcome`, `box`, `unchecked` and `detail`. `outcome` is `filed`,
`already held`, `still newer`, `collided` or `left`. `box` is `inbox` or
`quarantine` for a filed message. `unchecked` names the checks that could
not run, and `detail` says why a message was left.

*When the relay's numbering restarts.* The relay numbers the mail it holds,
and your cursor, `relays/<name>/cursor`, is the number of the last message
this machine fetched there. Every listing gives what is after your cursor,
each number above the one before, and says the lowest and highest numbers
the relay holds for you. A cursor above the highest is past everything there.
That happens on an ordinary day, when you `auu rm` the newest message kept on
the relay. It also happens when the relay's operator deleted its database and
its numbering began again. An upgrade does not do that. The next fetch tells
the two apart by asking the relay for its list without the messages and
matching each row to what you already have from it. When it all matches, the
cursor goes back to the relay's highest number and nothing is said. When it
does not, the fetch starts again from the relay's lowest number in the same
run and says so once:

    relay.example: this machine's cursor was 9 and the relay's mail is numbered 1 to 3, so the cursor was reset and mail is fetched from the beginning; nothing is delivered twice here

A message you already have is recognised by its own id and left as it is,
read or not, and one you removed here with `--local-only` stays removed. One
you had let go from the relay, from a channel set not to keep or with `auu rm
--remote-only`, is let go again. What the relay no longer holds stops saying
`on relay`. A stranger's stream whose body you left there and the relay lost
says `body not fetched, and gone from the relay`, and `quarantine trust`
says the body is gone rather than asking the relay for it.

Every fetch recognises mail it already has this way, not only after a
reset. A message the relay serves again, because it lost an acknowledgement
or because the cursor was set back, keeps its record and its read mark and
is not counted as new. So a reset that is cut off part-way, by a wait's
deadline, a dropped connection or Ctrl-C, leaves nothing to put right: the
next fetch carries on from where it stopped, delivers each new message once,
and only the sentence is not said again. A message is recognised by its own
id and its signer together: one that arrives under the id of a message you
have, signed by somebody else, is not that message. It is kept under
`damaged/` and said to be, and the message you have is left as it was. `auu wait`, `auu
watch --fetch` and `auu serve` fetch the same way. A plain `auu watch`
reports only the mail you do not have, and moves nothing.

A cursor inside the relay's span, with mail before it that was neither
fetched nor left there on purpose, is different. That cursor was set by
hand or copied from a machine that had fetched further, and nothing the
relay says can tell whether the gap was meant, so it is yours to put
right. That one is refused, with the count and the command that puts it
right, at exit 5.

*Setting a cursor by hand.* `auu cursor show` prints each relay's cursor
beside what the relay holds, its lowest and highest numbers and how many,
or a dash for a relay it could not ask. `--relay NAME` narrows it and
`--json` gives it to a script. `auu cursor reset --relay NAME` sets that
relay's cursor to 0, or to `--to N`, after saying what the next fetch will
then fetch, and asks first. `--yes` skips the question for a script of
your own, and without a terminal and without `--yes` it is refused. `--to`
is a relay message id in decimal. A relay this home has added but never
joined has no cursor, and reset says to `auu register` there first. It
never fetches: `auu inbox --relay NAME` does. Mail you already have is
recognised by that fetch and not delivered again, so a cursor set too low
costs a listing and no mail.

### 1.6 An expert on a channel

A channel can be answered by a program rather than by a person, Claude Code
in the case it was built for. `auu serve` hands every message that arrives
on one to a handler running in a git worktree of the project's checkout,
and sends back what the handler printed:

*Listing 1.6a*
```
auu serve check                    # read serve.json and say what it would serve
auu serve --once                   # one round: fetch, answer what is pending, stop
auu serve                          # the service: hold on the relay and answer as mail arrives
```

Which channels, which checkout and which program is a file in the home,
`serve.json`. A `read-only` channel answers with text and shares one
worktree, so its handler can keep one warm session for the whole channel. A
`side-copy` channel gives every thread a worktree of its own. It attaches
the thread's whole change so far as a patch the asker applies with `git
apply`. Serve never opens a thread and never answers a reply to anything
but its own, so two experts pointed at each other stop. It answers only
peers, since quarantine is never read. `docs/serve.md` is the command, its
file and its state. `docs/creating-experts.md` is how to set one up well,
and `docs/serve-claude.sh` is the wrapper the guide starts from.

### 1.7 Watching

To be told when something happens, rather than asking:

*Listing 1.7a*
```
auu watch                          # returns when mail arrives, on any relay you are on
auu watch --event directory        # ...or when a colleague changes their channels
auu watch --channel bugs --fetch   # only bugs, and fetch what arrived
```

A watch returns on the first poll that finds an event, reports every event
from that poll, and exits 0. At `--timeout` it prints
`nothing happened in 10m0s` and exits 3, the code `auu wait` uses for the
same thing. The timeout is 10 minutes unless you say, or `0` for no limit,
since a watch under a supervisor sits all day. `auu wait`'s `--timeout`
must be more than nothing, since a wait is over when it ends.

There are two kinds of event. A `message` is a message the relay holds
that this machine has not fetched, a post or a placed stream. It is said
with its relay, channel, kind, size and relay id. A `directory` is a
peer accepting a different channel directory on the relay. It is said
with who, when it was issued, which channels were added, removed and
updated by name, and the channels as they are now. `message` is the
default. `--event directory` asks for the other, both flags for both.
`--channel NAME` keeps only messages under that channel. `--peer NAME`
narrows a directory watch to that peer, or `self` for your own directory
changed from another machine. Without it every peer on your list is
watched, and a peer who has not admitted you is named once on stderr and
left alone. So is a peer whose directory this build cannot use, at the
start or on a later change, with one of the three sentences `auu channel
ls PEER` gives and `; their channels are not watched`; the watch runs on
for the others. Your own directory served wrong still ends the watch,
exit 2, since it is this home's own document.

The baseline is your cursor. Anything a relay holds that this machine has
not fetched is an event, reported at once, so `auu inbox; auu watch` has no
gap. A watch changes nothing: no fetch, no cursor moved, no lock taken. It
says what the relay said, and you run `auu inbox`. Or pass `--fetch`, which
fetches from the relay that spoke and carries what was delivered with the
report. Plain output is one line per relay per channel, `work: 2 messages
in "bugs" (1.2 KiB, 40 MiB)`. A directory is `work: bob added "cfp", closed
"bugs", removed "old"`, or `work: you changed your channels elsewhere
(issued T)`. With `--fetch` the delivered messages follow as the inbox
lists them. `--json` is one document, `{"events": [...], "waited": "12s"}`,
empty at the timeout. Each `message` event carries `messages` under
`--fetch`. Each `directory` event carries `channels` as `auu channel ls
PEER --json` shapes them.

The watch asks each relay to hold the listing open until something
arrives, for up to the interval, so an event comes back when it happens.
The interval is `--interval`, 20 seconds, at least 5. Every relay you are
on is watched at once, and the first to answer ends the watch. A relay
over its cap on holds answers at once and is polled at the interval
instead, which the watch cannot tell and does not need to.

There are no
delivery receipts, and cannot be. The relay records no sender on a
message, so it cannot say whose was collected — with one exception, a
knock, whose row names its knocker until the fetch that acknowledges it.

### 1.8 Several relays

One home can be on any number of relays, a company's and your own, say, with
one identity, one peer list and one inbox. That last part is the point. Your
mail is your mail, and which relay it came through is a detail of delivery.

*Listing 1.8a*
```
auu relay ls                       # what this home knows; * is the default
auu relay add https://relay.example:9443 --name work --anchor HASH
auu relay default work             # what commands mean when they are not told
auu relay show work
auu relay rename work office
auu relay rm work
```

An enrolment token names its relay, so `auu enrol --name you TOKEN` adds it
and registers you there. The first relay a home joins becomes its default and
later ones do not. Without `--name` a relay is called after its host, made
into a name the rules allow. The rules allow letters, digits, `.`, `_` and
`-`, beginning with a letter or digit. So `https://[::1]:8443` becomes `1`,
and a second relay on the same host gets its port, then a number. The
command prints the name it chose, and `auu relay rename` changes it.

Which relay a command uses is `--relay NAME`, then `AUU_RELAY` in the
environment, then the default. A name may be shortened to a unique prefix, and
a relay's URL works wherever its name does.

*Listing 1.8b*
```
auu send --to bob --relay personal 'over here'
AUU_RELAY=personal auu lookup bob
```

Commands that do one thing at one place, `register`, `cert`, `anchor`,
`lookup` and `send`, use the selected relay. Commands that read your mail or
set your policy, `inbox`, `wait` and `allow`, cover every relay you are
registered on, unless `--relay` narrows them. A relay that cannot be reached
during `auu inbox` is named on stderr and skipped. The mail on the others
still arrives.

A reply goes back the way the message came, without being told, because that
is where the other person's mailbox was. `--relay` overrides it. And a send to
somebody with no mailbox on the relay you chose says where their mail has been
arriving from instead:

*Listing 1.8c*
```
bob is not registered on work; mail from bob has arrived through personal
```

**One home is one identity.** The same fingerprint is registered on every
relay the home joins, which is what makes one peer list and one spool mean
anything. It has a cost worth knowing. Anybody who can see two of those relays
can tell that the same person is on both. Being a different person on each
relay is what a second `AUU_HOME` is for.

**A peer on another relay.** If your relay's operator has peered with the
relay somebody else is on, you can write to them without joining it. The
address is their name with the relays to go by way of in front, separated
by `!`:

*Listing 1.8d*
```
auu send --to 'bar!bob' 'hello over there'
auu send --to bob --via bar 'the same address, for a script'
auu send --to 'bar!baz!bob' 'two hops'
```

Quote it: `!` is history expansion in an interactive shell. `--via` is the
same address given separately, for exactly that reason. Giving the relays
in both at once is refused rather than merged.

**Each name is what *your* relay calls that relay**, and only the first one
is. There is no global directory of relays: `bar` is the name your relay's
operator gave that neighbour when they peered with it, and the second name
in `bar!baz!bob` is what *bar* calls the next one, which you have to have
been told. Ask whoever gave you the address.

A peering has two halves and only one of them is listed, which is worth being
exact about because the names look alike. The relays your relay *dials* — the
ones a path's first name is resolved against — are its operator's, kept in the
directory it dials from and served by no route, so a name that is wrong there is
found by sending, and comes back as `no neighbour named "bar" on this relay`
before anything is queued. The relays your relay *accepts* forwarded mail from
are listed, by `auu relay couriers`, because you have to admit them to be
reachable from off your relay. [*Admitting a courier*](#18-several-relays) below
is that. An operator normally uses one name for a neighbour in both halves, but
nothing can make them, so a name from the listing is a good guess at an address
and not a promise.

Your relay queues the message and answers at once. The id you get back is
a row in that queue rather than a message in a mailbox, and the `sent`
record keeps the path beside it. `auu queue` is what shows that row
afterwards, and `auu inbox` says one line while it is waiting. If a hop
cannot deliver it, that comes back later, not in the answer to your send.

At the other end they see a `via` line on `auu read` and can answer with
`auu reply`, which goes back the way it came. [1.5](#15-receive) says what
that rests on and how they answer when it cannot.

What does not cross a relay yet is a large message. A stream is an upload
held open at the relay it is going to, and nothing carries one to a
neighbour, so `--stream` on a path, or a message big enough to become one —
64 KiB unless you have changed `stream_threshold` — is refused at your
terminal:

*Listing 1.8e*
```
a large message does not cross a relay yet
```

A channel name on a path is sent as written and not checked here. Which
channels somebody has is theirs to publish to the senders they admit, and
the relay that knows is the last one, not yours. A name that hop refuses
comes back later as a failed message rather than as an error when you send.

Your terminal checks what it can: every name is a relay name, no relay is
named twice, and an address names at most 32 relays, which is the
protocol's ceiling. A relay may allow fewer. `courier.max_hops` is 8
unless its operator changed it. Nothing on the wire says what a given
relay allows, so an address between the two passes here and is refused by
the first hop, in that hop's words.

**Admitting a courier.** If your mailbox is restricted — if you have run
`auu allow push` — then nothing forwarded reaches you until you say which
relays may carry it. That is not the same as trusting the people behind them,
and the difference is the whole of why it is a separate step.

A relay cannot open an envelope. When mail arrives from another relay, the only
sender your relay can prove is the neighbour that handed it over, so that
neighbour's identity — its *courier* — is what your allow list is asked about.
Admitting one means "mail that came through this relay may be delivered to me",
whoever sent it. It is the one place an allow list means something coarser than
the fingerprints in it.

It means one thing more, and it is better read here than discovered. Your allow
list is one list, and your relay asks it one question: may this fingerprint put
something in this mailbox. So the courier's own key may also write to you
directly, as any sender would. That message lands in quarantine rather than your
inbox. What decides that is your peer list, which admitting a courier does not
touch. So you see an unknown sender and decide, exactly as you would for a
stranger. The difference admitting makes is that a restricted mailbox refuses a
stranger at the relay and will not refuse this one.

Your relay will tell you which relays it accepts forwarded mail from:

*Listing 1.8f*
```
auu relay couriers                 # and --relay NAME, and --json
auu allow add --courier bar        # admit one, by the name your relay gives it
auu allow rm --courier bar
auu allow push                     # nothing changes at the relay until you do
```

`auu relay couriers` prints each one with its fingerprint and whether you
admit it already. The names are **your relay's own**. A relay calls each
neighbour whatever its operator chose, the same relay may be called something
else at the next hop, and what a relay calls itself is published nowhere. So a
name from this listing is good for addressing mail through your relay and for
nothing else. It is also the first element of a path: `bar!bob` reaches bob
through the neighbour your relay calls `bar`.

`auu allow add --courier` asks your relay for the fingerprint rather than
taking your word for it, so a name your relay does not have is refused with the
names it does have. It then says what admitting the courier lets through and
asks, and writes nothing unless you agree or pass `--yes`. What it writes is a
line in `relays/<name>/couriers`, and `auu allow push` sends your peers and that
relay's admitted couriers as one list. Each relay has its own file, because a
courier's fingerprint means nothing at another relay.

If you admit nobody, forwarded mail is refused and the sender eventually reads
that their message could not be delivered, naming your relay's neighbour as the
hop that refused. If your list is not restricted at all — if you have never
pushed one — then every registered sender may post to you and forwarded mail
arrives without any of this.

### 1.9 Encrypting your keys

`identity.json` holds your two secret keys, and each `relays/<name>/cert.json`
holds that machine's certificate key, all in the clear behind a file mode. A
backup, a snapshot, a synced home directory or a stolen laptop yields every one
of them. You can put them under a passphrase:

*Listing 1.9a*
```
auu passphrase set                 # asks twice; encrypts this home's keys
```

That would be unbearable if every command then asked for the passphrase. An
agent runs `auu` many times an hour, and a passphrase typed on each run is a
passphrase in a script within a week. So `auu` has an agent of its own, in
the spirit of `ssh-agent`. `auu passphrase set` starts it. It holds the
unlocked keys in memory. It performs every private-key operation for the
commands that ask, over a socket only your own processes can reach, for a
fixed time after you unlock it:

*Listing 1.9b*
```
auu unlock                         # asks once; the agent reads for 8 hours
auu unlock --ttl 2h                # or for as long as you say; 0 means until 'auu lock'
auu unlock --send                  # asks again; the agent sends as well, for 10 minutes
auu unlock --send --ttl 0          # or until 'auu lock', for a machine that answers unattended
auu lock --send                    # stop sending now, keep reading
auu lock                           # drop the keys now
auu agent status                   # running? which scope? until when?
auu agent stop
auu passphrase change              # rewrites one file; nothing else on disk changes
auu passphrase remove              # back to keys in the clear
```

An unlock has a scope. `auu unlock` unlocks to **receive**, for eight hours
by default. The agent opens your mail, signs the handshake with your
machine's certificate, and signs the requests that list, fetch, watch and
acknowledge. Those are `auu inbox`, `auu wait`, `auu watch`, `auu rm`,
`auu lookup` and the rest of what reads. It refuses to sign anything that
originates: a message, a reply, a stream, a channel directory, an allow
list, an enrolment, an administrator's request. `auu unlock --send` unlocks
to **send**, everything the agent can do, for ten minutes by default. When
that ends the agent is back to receive for the rest of its eight hours,
not locked. `auu lock --send` ends the window early. The agent decides by
what it is asked to sign under, never by who is asking, because anything
running as you can ask. Every construction in this project puts its domain
at the front, and a relay request its method and path.

The point is your AI. While the agent is unlocked, any process running as
you can have it sign. A message your AI reads could be written to talk it
into sending one you never meant, signed as you. No confirmation the agent
could ask for in-band would help, since the same process can answer it.
The one thing an AI cannot do is type your passphrase, so that is what
originating costs. It is one command from you, the way `ssh-add -c` asks
for a touch. Your AI can read the inbox and the quarantine all day and
cannot originate anything until you do. Sending from your own terminal is
the same command first.

While the agent is unlocked in the right scope, every `auu` command, yours,
a script's or your AI's, works as it always did. When it is locked, a command
that needs a key asks you for the passphrase if you are at a terminal.
Otherwise it stops with exit code 4 and one sentence. When it is unlocked to
receive and the command originates, it stops with exit code 4 and the other
one, terminal or not, since the unlock it needs is a decision:

*Listing 1.9c*
```
auu: your identity is locked: run 'auu unlock' in your own terminal
auu: the agent is unlocked to receive; run 'auu unlock --send' at a terminal to send for the next 10 minutes
```

Those two sentences are the whole of the arrangement with an AI. It never
sees the passphrase and cannot unlock anything. The `connect` skill tells
it to ask you to run the command the sentence names and then try again. It
also tells it to check `auu agent status --json` for `scope` before its
first send.

`auu unlock` reads a passphrase from the terminal, from
`--passphrase-file` for a secret manager, or from standard input when that
is a pipe. No other command reads one from anywhere but a terminal, and
none takes one as an argument or from the environment. At your own
terminal a command that sends may ask you twice when the agent is locked.
It asks once for the passphrase, which unlocks to receive and says so in
the prompt, and then in the sentence above for `auu unlock --send`. That is
because the send unlock is a decision you make, not one a command makes
for you on the way to something else. One command is an exception on
purpose. `auu enrol` on an encrypted home registers this machine, which is
a human act. So at a terminal it asks for the passphrase into send scope
itself rather than sending you off to run the unlock.

Commands that need only your public half, `auu id`, `auu id export`,
`auu peers`, `auu relay`, `auu anchor`, `auu inbox --no-fetch`, `auu read`,
`auu extract` and `auu quarantine ls`, never touch the agent and work with
the keys locked. `auu id` says `secrets: encrypted, unlocked to receive until
17:04`, `encrypted, unlocked to send until 17:14 (receive until 01:04)`,
`encrypted, locked`, or `not encrypted`. `auu id --json` carries
`encrypted`, `locked` and `scope` for a script to check before it starts.

What this protects, said plainly. At rest, every private key is ciphertext
under a passphrase that is stored nowhere. `home.key` is a random key
encrypted under the passphrase with the same Argon2id-then-PBKDF2 derivation
`auu-ca` uses. Every key file is sealed under that key with AES-256-GCM,
so a change of passphrase rewrites one file. While the agent is unlocked, any
process running as you can *use* the keys by asking it, exactly as with
`ssh-agent`, and cannot *read* them. The files are ciphertext, the keys never
cross the socket, and the agent refuses debugger attachment and writes no
core file. Root can do anything. A keylogger at unlock is not defended
against. A process that asks the agent to sign something you did not mean
is held to the scope. In receive scope it can fetch, and it can acknowledge,
which is to say delete, mail on the relay, and nothing more. In the ten
minutes after `auu unlock --send` it can originate as you, which is what
the window is short for. Two things are outside this. A home that was never
encrypted has no agent and no boundary. Its keys are files, and any process
running as you can read them. And a passphrase in a file
(`--passphrase-file`) is a passphrase your AI can read. So a person who
keeps one has opted out of the arrangement above, whatever the scope says.
And one thing stays as it was. `inbox/` and `sent/` hold your mail after it
has been opened, in the clear. Encrypting the keys protects the keys.

A running agent looks at its socket every thirty seconds. When the
socket is gone, when another file or another agent's socket stands at
its path, or when its runtime directory is gone or is now a file, it
locks, dropping the keys, and stops. It leaves alone whatever stands
there, removing only a socket that is still its own. A path it cannot
read it says once in its log, and goes on serving.

Encryption is optional and a home that never runs `auu passphrase set` is
untouched, byte for byte. A home that has can be read only by a build with
this feature. An older `auu` sees an identity file with no keys in it.

On Linux and macOS the agent refuses connections from any other user by the
kernel's word (`SO_PEERCRED`, `LOCAL_PEERCRED`) and refuses debugger
attachment. The client asks the same of the agent: before `auu unlock`, or
any command that reaches the agent, sends a byte, it asks the kernel who
answers the socket, and a socket another user answers is refused by name,
its uid and yours given, with nothing sent. Its socket, lock and log live in `$XDG_RUNTIME_DIR/auu`, or,
when `XDG_RUNTIME_DIR` is unset, in `auu` under the temporary directory,
which on Linux is `/tmp/auu`, where every user of the machine can make a
name. That directory must be a directory of your own and never a symbolic
link. Before it makes anything there, every command that reaches the
agent looks at what stands at the path without following a link. A link
is refused by name, even one that points nowhere, since a link another
user planted at `/tmp/auu` could point at a directory of yours and have
the agent write there. The directory is then opened without following a
link, and its owner and mode are judged on what was opened. A directory
another user owns is refused, and so is one of yours with any group or
other permission bit, since what another user put there while it was
open, a socket bound to take the passphrase, would outlast a chmod:

*Listing 1.9d*
```
auu: agent: /tmp/auu is a symbolic link, not a directory; remove it, or set XDG_RUNTIME_DIR to a directory of your own
auu: agent: /tmp/auu belongs to another user; set XDG_RUNTIME_DIR to a directory of your own
auu: agent: /tmp/auu is mode 0755: the agent's directory is yours alone, and one other users can reach may hold what they put there; look at what is in it and make it 0700 (chmod 0700 /tmp/auu), or set XDG_RUNTIME_DIR to a directory of your own
auu: agent: /tmp/auu/3f9a1c2e7b04d815.sock is answered by uid 1002, not by you (uid 1001); nothing was sent. Remove it, or set XDG_RUNTIME_DIR to a directory of your own
```

A loose directory used to be made 0700 without a word. Look at what is in
it before you make it 0700: a socket or a file you did not make there is
another user's. The lock file and the agent's log in it are opened never
through a link and must be regular files, on Linux and macOS; on Windows
the directory under `%LOCALAPPDATA%` is your own and is what is relied on.

A link you made yourself you can remove. One another user put in `/tmp`
you cannot, any more than their directory, and `XDG_RUNTIME_DIR` set to a
directory of your own is the way past both.

On Windows the socket is an `AF_UNIX` socket under
`%LOCALAPPDATA%\auu`, which is yours by construction. That directory is
the whole of the same-user check, for the agent asking who called and for
the client asking who answers. Windows gives a socket no peer
credentials, and there is no attachment guard. CI runs the agent's tests on
Windows. Nobody has used it there by hand.

### 1.10 Exit codes

| code | meaning |
|------|---------|
| 0 | success |
| 1 | bad usage, unknown peer, or missing identity |
| 2 | could not reach the relay, or it refused |
| 3 | `auu wait` or `auu watch` timed out |
| 4 | your keys are encrypted and locked: run `auu unlock` in your own terminal; or unlocked to receive and this command originates: run `auu unlock --send` at a terminal, which lasts ten minutes |
| 5 | a file in this machine's auu home is damaged, has been altered, or has an unsafe mode; a person needs to look, and the message names the file |

### 1.11 Rooms

A room is a list of recipients saved under a name. It is kept in
`rooms.json` in the home and nowhere else. Nothing of it is posted, so no
relay learns that a room exists. A message sent to a room is a message to
several, as if each member had been named. Its recipients see who it went
to, as they see it for any message to several, and not the room's name.

*Listing 1.11a*
```
auu room create team bob carol 'bar!dave'
auu room ls
auu room show team
auu room add team erin
auu room rm team carol
auu room delete team
```

`room create NAME MEMBER...` makes a room, and `room add` adds to one. A
MEMBER is a peer as `--to` takes one: a name, a fingerprint, a short id or
`self`. Somebody on another relay is `RELAY!NAME`, with the nearest relay
first, and the room keeps those relays for them. Everybody but `self` must
be on your peer list when the room is made or added to, since a room holds
only people this machine can seal to. `room ls` prints each room and how
many are in it. `room show` prints who is in one, by the peer list's name
and the short id, with `by` and the relays for a member who has them.
`room rm` takes members out, named as the peer list names them, or by the
short id `room show` prints for somebody no longer on the list. The last
one out deletes the room. `room delete` asks first and removes the list
alone: the peers stay on your peer list. `room ls` and `room show` take
`--json`.

A room's name has a peer name's form: letters, digits, `.`, `_` and `-`,
at most 64 bytes. Rooms and peers share one set of names. A room may not
take a peer's name, and a peer may not be added under a room's. A name of
eight or more hex characters is refused, since it could be the start of a
fingerprint. A room is named whole, in any case, and never by a prefix. A
home holds at most 256 rooms, and a room 1 to 32 members. A `rooms.json`
that does not read, or breaks a rule, is refused by name with exit 5.
Until it is fixed, `auu send` and `auu peers add` refuse too, since any
name either is given might be a room in it: `auu send` with exit 5, and
`auu peers add` with exit 1, as it says any refusal of the add. A
`rooms.json` a later auu wrote is not damaged, and both refuse it with
exit 1, saying `a later auu wrote it`.

*Listing 1.11b*
```
auu send --to team --subject 'the release' 'out on Friday'
auu send --to team,frank 'and frank too'
```

`--to` takes a room's name wherever it takes a peer's. A name is looked
for among the rooms first, whole and in any case, and then on the peer
list as before. A name with `!` in it is an address and never a room.
The room's members take its place in the list, in the room's order, each
with the relays the room keeps for them. A room and other names mix, in
one value or in several `--to`. `--via` beside a room is refused, since a
room carries its own addresses: `team is a room, which carries its own
addresses; send to it without --via, and change a member's relays with
auu room rm team NAME and auu room add team 'RELAY!NAME'`. A room named
twice is refused on its own, before anything is counted: `the room team
is named twice; name it once`.

Every check is made before anything is sealed. A member no longer on your
peer list refuses the send, naming the room and the two remedies: `the
room team holds SHORT, who is not on your peer list, so nothing was sent;
remove them with auu room rm team SHORT, or add them again with auu peers
add`. Somebody in a room and named as well, or in two rooms, is refused
naming both, in the order they were given on the command line: `carol
(SHORT) is in the room team and named as "carol"; name each once`. A room
and a peer that share a name, as an older auu or a hand edit can leave
them, name nobody for certain, and a send to it is refused: `team is a
room's name and your peer SHORT's too, so it names nobody for certain;
one of the two must go: auu room delete, or auu peers rm`.

The limits are counted after the rooms are expanded. More than thirty-two
recipients is refused, `40 recipients once the room team is counted; a
message may go to at most 32`. More than the relay takes is refused naming
the relay and its number, `N recipients once the room team is counted;
RELAY takes at most MAX in one message (its max_recipients)`. A room of
one is a message to one, with no list on it, sent by the relays the room
keeps for that member.

A room with a member on another relay cannot carry a large message. A
message large enough to become a stream does not cross a relay, so the
whole send is refused before anything is read. For a room of several the
sentence names the member, with the largest attachment after it: `a large
message does not cross a relay yet, and dave is reached by bar; send them
a smaller message on its own`.

`auu read`, `auu wait` and `auu quarantine show` of a message to several
print `room:` and a room's name, after the `to:` list, when the other
people on it are exactly a saved room's members. The other
people are the sender and every recipient, with you taken out, against the
room's members with `self` taken out, in any order. For a message you
sent they are its recipients. Two rooms with the same members name the
first in the file. Their `--json` carries the name as `room`. It is this
machine's own label for a list the `to:` line already shows, and it says
nothing the sender sent. The inbox listing and `auu quarantine ls` are
unchanged, and their `--json` carries no `room`.

`auu reply --all` is unchanged by rooms. It answers the sender and every
other recipient through the relay the message came by. It takes no `--to`
or `--via`, since a reply goes back the way the message came. A recipient
on another relay is reached by a new message to `'RELAY!NAME'`, or to a
room that holds them, since a room carries an address for each person.

Rooms are this home's alone. A second machine of the same identity has its
own `rooms.json`, as it has its own peer list. Copying the home to it
copies the file as it stands. After that a room changed on one machine is
not changed on the other.

## 2. Local state

Everything lives in `~/.auu`, or `$AUU_HOME` if set. The directory is mode 0700
and every file in it is 0600, and `auu` checks. A key file that group or
others can read is refused by name with the `chmod 600` that puts it back.
The key files are `identity.json` in its plain form, `home.key`,
`identity.key` and a relay's `cert.json`. A home that group or others can
write is refused the same way, with `chmod 700`. Both exit 5, since `auu`
wrote them 0600 and 0700 itself and a wider mode means somebody changed it.
`authorized_peers` and the spool hold nothing secret, so a writable one is a
warning, once, and the command goes on. The check is Unix's. On Windows,
Go's file modes say nothing about who can read.

| path | contents |
|------|----------|
| `identity.json` | your secret keys; with a passphrase set, only your name and public bundle |
| `home.key` | with a passphrase set: the home key, encrypted under the passphrase |
| `identity.key` | with a passphrase set: your secret keys, sealed under the home key |
| `config.json` | your name, the default relay, and optionally your editor; a key `auu` does not write is refused by name with exit 5, and one of the keys a home from before v0.11.0 held its one relay under — `relay`, `trust_anchor_spki` — is refused as that, with the fix |
| `COMPOSE_MSG` | the last message composed in the editor |
| `authorized_peers` | one export line per peer, the trust anchor; a peer added on a vouch has a `# vouched for by` comment above its line, which `auu peers rm` takes with it |
| `vouches/<fingerprint>.json` | a vouch a peer gave you to keep, one per voucher, named by the voucher's fingerprint: the document and the signature as they arrived, the newest kept; `auu knock --vouch` carries it |
| `rooms.json` | your rooms, saved lists of recipients under a name, each member by fingerprint with the relays to go by; this machine's alone and never posted, at most 256 rooms of 1 to 32 members; `auu room` keeps it, and a file that will not read, or that breaks a rule, is refused by name with exit 5 |
| `channels.json` | your channel directory as this machine last signed it, `issued` included; `auu channel push` signs it under that time again, and a file that will not read, or that breaks a rule, is refused by name with exit 5 |
| `card.json` | your card as this machine last pushed it, `issued` included: your name and whether the relay may list you and let a knock through; `auu card push` signs it again with the words a typed flag changes, and a file that will not read, or that breaks a rule, is refused by name with exit 5 |
| `channel-settings.json` | this machine's own policy per channel: whether mail fetched from it is left on the relay; absent, and every channel keeps |
| `relays/<name>/relay.json` | one relay: its URL, when it was added, and what this machine has learned about its certificates |
| `relays/<name>/trust_anchor.pem` | that relay's pinned trust anchor, when it has one; `relay.json` records its hash, and a file here with no hash recorded is refused as an edit, not taken as unpinned |
| `relays/<name>/cert.json` | this machine's client certificate for that relay, and its key — sealed under the home key when a passphrase is set |
| `relays/<name>/cursor` | how far that relay's mailbox has been drained; one above everything the relay holds is reset by the next fetch (1.5, *When the relay's numbering restarts*), and one that skipped mail inside the relay's span is refused with the count and `auu cursor reset --relay NAME`, exit 5; `auu cursor show` prints it and `auu cursor reset` writes it |
| `relays/<name>/allow_pushed` | when this machine last pushed a signed allow list to that relay, one RFC 3339 line, so a fetch can tell a relay that never had one from a relay that has lost it; `auu allow clear` removes it |
| `relays/<name>/card_pushed` | the same for the card; `auu card clear` removes it |
| `relays/<name>/left-behind` | the messages `auu rm --local-only` removed here and left on that relay, one per line: the relay's id, the message's own id, the time the relay received it, its size and the fingerprint of its signer (`-` when the record it was removed from could not be read). The fetch does not mistake them for mail the cursor has skipped, and a reset does not deliver them again; pruned when the relay no longer lists them. A file of bare ids, from before, is refused by name; deleting it costs that a message you removed here alone may come back once |
| `relays/<name>/fetch.lock` | held while a fetch from that relay runs, so two `auu inbox` at once take turns; the second waits up to a minute and then says so |
| `inbox/`, `sent/`, `quarantine/` | the message spool, one JSON file each; a record that will not read is said to be, once, and left out of the listing |
| `inbox/<id>.d/` | a large message's files, written straight to disk |
| `outbox/` | what is sealed but not yet delivered, waiting for `auu send --resume`; `auu outbox` lists it |
| `damaged/<relay>/<id>.bin`, `.json` | a message your key could not open, as the relay served it, with a record of which relay's message it was, when, and why in a word — `did not decrypt`, `not addressed to this key`, `sender signature failed`, `malformed`, `newer: section "NAME"` for a message with a critical section this build does not know, which `auu damaged reopen` opens once `auu` is updated, its record also saying the kind, channel, via and size the relay listed it with, or `misfiled` for a message the relay listed under a channel it was not sealed for, or listed as a kind its sealed record is not — a knock that is not one inside, or one that is inside a row listed as an ordinary envelope; a stream keeps its manifest chunk only. `auu damaged ls` lists them and `auu inbox` says how many are there until you remove them; nothing here is opened again but a `newer` one; the directory holds at most 64 MiB and at most 1,024 kept messages, the oldest going first, and a message that alone exceeds that is not kept, which the warning says; a file there that is not a kept message is not counted and `ls` names it |

The files `auu` keeps for itself are read strictly: `identity.json` plain or
locked, each relay's `relay.json` and `cert.json`, `channel-settings.json`,
serve's ledger and every record in the spool. A key this program does not
write, a key given twice, a key in another case or anything after the
closing brace is refused with the file named, never read as if the key were
absent; so a hand edit that misspells a key fails at the next command that
reads the file, and the fix is to spell it as `auu` wrote it. The channel
names in `channel-settings.json` are the one exception: they are
case-sensitive, as the signed directory's are, so `Bugs` and `bugs` are two
channels with a keep each, and only the same name given twice is refused.
Every key v0.15.0 to v0.17.0 wrote is still read, so an upgraded home reads
as before.
The message kept under `damaged/` is not held to this: it is kept because it
would not open, and `auu damaged reopen` tries it again as the fetch does.

`authorized_peers` is the file that matters. Nothing on the network can add to
it. Back it up alongside `identity.json`. Back up `home.key` and
`identity.key` too when you have set a passphrase, without which the other
two are ciphertext. It is one export line per peer. A line that will not
parse, most often one an editor or a mail client wrapped, is refused by its
number, with the question asked, by every command that reads the list.
`auu inbox` is included, and fetches nothing until the file is fixed.
`auu peers add` given a line with a break in it says to paste it as one
line.

Everything about one relay is in that relay's own directory. So removing a
relay is removing a directory, and backing one up is copying one. A home
from before v0.11.0 held its one relay's URL in `config.json` and that
relay's anchor, certificate and cursor loose in the root. Such a home is
refused by name at every command, exit 5, and is not moved to this shape.
Nothing on this machine is from before. The sentence names the file and
says what to do. Delete `config.json` and whichever of `trust_anchor.pem`,
`cert.json` and `cursor` are in the root, then add the relay again with
`auu relay add`. Or delete the home and run `auu init` again. A record in
the spool that names no relay, as every record from before did, is refused
the same way when it is read.

`cert.json` is the one file you should **not** copy to another machine, nor
between relay directories. One that records a different relay from the
directory it sits in is refused by name, before anything is dialled. The
refusal says the relay it was issued by and the
`auu register --relay NAME --token TOKEN` that gets one for this relay. It
is that machine's credential, and the point of it is that each of your
machines has its own. A second machine asks for its own with
`auu register --relay NAME --token TOKEN`.
