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

Restrict your relay mailbox to the people on your list:

*Listing 1.2c*
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

The third document you can push is your card, and nothing is pushed until
you say so:

*Listing 1.2d*
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
no card means. Saying you may be listed is saying you may be found by
every identity the relay admits, and what that is worth depends on the
relay: `auu relay show` says whether it invites by token or registers
anyone, and so does `auu lookup`. As with the allow list, a card edited
on the relay's host stops verifying, which the relay reads as `broken`
until you push again, and `auu inbox` tells you so.

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
ships a name a receiver would write differently. Above 64 KiB in all, the
message goes as a stream. It is sealed to `outbox/` first, then uploaded
in one request per attempt, the whole of it or the rest of it from where
the relay's copy ends. An attempt that is interrupted is tried again on
the spot. `auu send --resume` finishes what a failed command left. It asks
the relay by an attempt from zero. It resumes once from the partial the
relay kept when it kept one, which it does for an attempt past its
threshold, within sixty seconds. Otherwise it opens anew for the same
sealed bytes. Nothing about the command changes. An attempt has no clock
but the link's. The upload runs for as long as bytes keep moving. It is
cut only when the relay takes none for sixty seconds, the relay's own
stall window, with the sentence `the relay stopped taking the upload: no
byte was read for 60 seconds`. After that the next attempt asks where the
relay's copy ends.
The download of a stream on the receiving side runs under the same rule,
`the relay stopped sending the stream: no byte arrived for 60 seconds`,
and resumes by range from where it stood. Every other request to the
relay is answered within two minutes or fails.

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
auu channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]
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
later, under the same signature. Two machines of one identity are kept from
writing over each other. Every edit first asks each relay what it holds. A
relay holding a directory issued later than this machine's stops the edit
with `work holds a directory issued T, newer than this machine's; run 'auu
channel pull --relay work' to take it first`. `pull` takes that directory
into the local file, and the edit goes through after. A directory or an
allow list is held to 1 MiB as it is sent, the relay's cap on the two
routes. A full directory of 64 channels at every limit is about 565 KB on
the wire and a full allow list about 157 KB, so what `auu` signs always
fits. A document that does not fit (`the directory is N bytes as sent,
over the relay's cap of 1048576; nothing was sent`) is one another tool
indented.

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
T`, with the time in your zone. Each is exit 2, as a refused allow list is,
and nothing was queued.

`auu channel keep NAME off` says that mail fetched from that channel is
acknowledged away on the relay at the fetch. `on`, which is the
default for every channel, leaves it queued there until you remove it with
[`auu rm`](#15-receive). It is this machine's own policy. Nothing is signed,
nothing is pushed, no relay is told, and the command works with the keys
locked. It lives in `channel-settings.json` in your home, so a copy of the
home takes it to a second machine. `auu channel pull` never touches it. The
name need not be a channel your directory still holds, since mail queued
under a deleted channel still arrives. A file that will not read is refused
by name with exit 5, and nothing is fetched under a guess.

`auu channel ls` prints your channels: name, description, period,
`open`, `opens T` or `closed T`, how many messages wait under each, and
`KEEP`, `on` or `off`. Then, per relay, it says whether it holds this
directory, an older one (`run 'auu channel push'`), a newer one from
another machine, or none. `auu channel ls PEER` prints a peer's channels
the same way, without counts, fetched from the relay and verified against
the key you hold for them. Somebody not on your peer list is a usage error,
since the relay is not a trust anchor. A directory that does not verify is
refused with `the directory work served for alice does not verify against
the key you hold; do not trust it` and exit 2. `--json` gives the
structure, with `open` as a boolean and `why` as the sentence.

### 1.5 Receive

*Listing 1.5a*
```
auu inbox                    # fetch from the relay and list
auu read MESSAGE-ID          # read one
auu extract MESSAGE-ID       # save its attachments
auu rm MESSAGE-ID            # remove it from the relay and from here
auu reply MESSAGE-ID 'It is missing. Open an issue against home-java.'
```

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
as `x-2.txt`.

A thread id works there too. `auu reply THREAD-ID` answers whatever is latest
on the thread, including your own last message. In that case it is a
follow-up to the person you sent it to. Latest is by when the message
arrived here and then by the relay's own numbering. It is never by the
time stamped inside it, which is the sender's word. `auu read` shows that
stamp as `sent:`, labelled the sender's clock, beside `received:`. A
message stamped in the future is refused when it is opened. Message and
thread ids are the same shape, and either may be shortened to a unique
prefix.

A reply carries the thread's subject unless you give it one of its own, with
`--subject` or by editing the `# Subject:` line in the editor. The thread is
still the thread. `auu read` then prints the thread's subject and the
reply's own indented beneath it. `--json` adds `thread_subject` beside
`subject`, which is always the message's own.

A fetch reads the mailbox in pages of up to 200 messages, and a page is
also bounded in bytes by the relay. It ends before an envelope that would
take it past the relay's `max_bytes`, admitting the first whatever its
size. So a page's envelopes never exceed `max_bytes` unless the first
alone does. `auu` learns the relay's `max_bytes` from its health answer
the first time it lists, and holds a page to twice that. A relay that does
not say its `max_bytes` is one from before this version and is refused by
name.

Mail from a sender who is not on your peer list is held back:

*Listing 1.5b*
```
auu quarantine ls
auu quarantine show MESSAGE-ID
auu quarantine trust MESSAGE-ID    # adds them to your peer list
```

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
your directory: "bug reports"`. Quarantine files the same way. A manifest
is read strictly. So a stream whose manifest carries a field this build
does not know is refused as malformed and kept under `damaged/`. That is
what a peer running something other than this `auu` looks like from here.

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
must be more than nothing, since a wait is over when it ends. There are
two kinds of event. A `message` is a message the relay holds that this
machine has not fetched, a post or a placed stream. It is said with its
relay, channel, kind, size and relay id. A `directory` is a peer accepting
a newer channel directory on the relay. It is said with who, when it was
issued, which channels were added, removed and updated by name, and the
channels as they are now. `message` is the default. `--event directory`
asks for the other, both flags for both. `--channel NAME` keeps only
messages under that channel. `--peer NAME` narrows a directory watch to
that peer, or `self` for your own directory changed from another machine.
Without it every peer on your list is watched, and a peer who has not
admitted you is named once on stderr and left alone.

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
instead, which the watch cannot tell and does not need to. There are no
delivery receipts, and cannot be. The relay records no sender on a
message, so it cannot say whose was collected.

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
first send. `auu unlock` reads a passphrase from the terminal, from
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

Encryption is optional and a home that never runs `auu passphrase set` is
untouched, byte for byte. A home that has can be read only by a build with
this feature. An older `auu` sees an identity file with no keys in it.

On Linux and macOS the agent refuses connections from any other user by the
kernel's word (`SO_PEERCRED`, `LOCAL_PEERCRED`) and refuses debugger
attachment. On Windows the socket is an `AF_UNIX` socket under
`%LOCALAPPDATA%\auu`, which is yours by construction. That directory is
the whole of the same-user check. Windows gives a socket no peer
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
| `authorized_peers` | one export line per peer, the trust anchor |
| `channels.json` | your channel directory as this machine last signed it, `issued` included; `auu channel push` signs it under that time again, and a file that will not read, or that breaks a rule, is refused by name with exit 5 |
| `card.json` | your card as this machine last pushed it, `issued` included: your name and whether the relay may list you and let a knock through; `auu card push` signs it again with the words a typed flag changes, and a file that will not read, or that breaks a rule, is refused by name with exit 5 |
| `channel-settings.json` | this machine's own policy per channel: whether mail fetched from it is left on the relay; absent, and every channel keeps |
| `relays/<name>/relay.json` | one relay: its URL, when it was added, and what this machine has learned about its certificates |
| `relays/<name>/trust_anchor.pem` | that relay's pinned trust anchor, when it has one; `relay.json` records its hash, and a file here with no hash recorded is refused as an edit, not taken as unpinned |
| `relays/<name>/cert.json` | this machine's client certificate for that relay, and its key — sealed under the home key when a passphrase is set |
| `relays/<name>/cursor` | how far that relay's mailbox has been drained; one past mail the relay still holds is refused with the count and the file to delete, exit 5 |
| `relays/<name>/allow_pushed` | when this machine last pushed a signed allow list to that relay, one RFC 3339 line, so a fetch can tell a relay that never had one from a relay that has lost it; `auu allow clear` removes it |
| `relays/<name>/card_pushed` | the same for the card; `auu card clear` removes it |
| `relays/<name>/left-behind` | the ids `auu rm --local-only` removed here and left on that relay, one per line, so the fetch does not mistake them for mail the cursor has skipped; pruned when the relay no longer lists them |
| `relays/<name>/fetch.lock` | held while a fetch from that relay runs, so two `auu inbox` at once take turns; the second waits up to a minute and then says so |
| `inbox/`, `sent/`, `quarantine/` | the message spool, one JSON file each; a record that will not read is said to be, once, and left out of the listing |
| `inbox/<id>.d/` | a large message's files, written straight to disk |
| `outbox/` | streams sealed but not yet delivered, waiting for `auu send --resume` |
| `damaged/<relay>/<id>.bin`, `.json` | a message your key could not open, as the relay served it, with a record of which relay's message it was, when, and why in a word — `did not decrypt`, `not addressed to this key`, `sender signature failed`, `malformed`, or `misfiled` for a message the relay listed under a channel it was not sealed for; a stream keeps its manifest chunk only. `auu inbox` says how many are there until you remove them; the directory holds at most 64 MiB, the oldest going first, and a message that alone exceeds that is not kept, which the warning says |

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
