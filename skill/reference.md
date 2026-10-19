# `auu` reference

Every command form, what each exit code means for an agent, the shape of
what `--json` prints, and the sentences that end a command. Read this when
a skill sends you here; the skills say what to do, this says what exists.

Three programs. `auu` is the user's own: identity, mail, channels, keys.
`auu-admin` administers a relay and is the operator's alone. `auu-ca` holds
the authority a relay's certificates come from and runs on the operator's
machine, never on the relay.

`auu` is the short name of `agentuucp`; they are the same program. If `auu`
is not on the PATH but `agentuucp` is, use that name instead everywhere
below.

## Every command

Identity, peers and lookup:

```
auu init --name NAME [--relay URL] [--anchor HASH] [--force]   # a new identity in this home
auu id [export]                                    # who you are; export prints the line a peer adds
auu id --json                                      # name, fingerprint, suite, locked, relays
auu enrol --name NAME [--label MACHINE] TOKEN      # identity and mailbox in one step
auu register [--token TOKEN] [--label MACHINE]     # a mailbox on a relay, or this machine's certificate
auu token show TOKEN                               # what a token carries, without using it
auu lookup FINGERPRINT|SHORT-ID|PEER [--json]      # what the relay knows about an id; adds nobody
auu listed [--json]                                # who on the relay chose to be listed, each entry verified here; adds nobody
auu peers add <export-line | @file | ->            # add a colleague; the user confirms the fingerprint
auu peers add --vouched MESSAGE-ID [--yes]         # add the peer a vouch in the inbox is for, on the voucher's word: the person's command, at a terminal; never run it
auu peers ls [--json]                              # who you can reach
auu peers rm <name|fingerprint>
auu peers fetch NAME|SHORT-ID|FINGERPRINT [--yes]  # add a peer found on the relay: the person's command, at a terminal; never run it
auu knock NAME|SHORT-ID|FINGERPRINT [--text "..."] [--vouch PEER]... [--yes]   # one message to somebody who has not admitted you, carrying up to four vouches you keep: the person's command, at a terminal; never run it
auu vouch PEER --to PEER [--relay NAME] [--json]   # send a peer the user's word that they hold another: the person's command; never run it
auu introduce PEER PEER [--relay NAME] [--json]    # a vouch each way, so each is told about the other: the person's command; never run it
auu vouch --ask PEER FINGERPRINT|SHORT-ID [--relay NAME] [--json]   # ask a peer whether they hold a key: the person's command; never run it
auu vouch answer on|off|show                       # whether inbox and wait answer a peer's question by themselves; off unless the person turns it on, and never yours to turn on
auu allow push                                     # tell the relay to take mail only from your peers and that relay's admitted couriers, signed
auu allow clear                                    # accept from anyone again
auu allow show [--json]                            # what each relay holds for you, verified with your own key
auu allow add --courier NAME [--relay NAME] [--yes]  # admit a relay that carries forwarded mail to you: the person's command, at a terminal; never run it
auu allow rm --courier NAME [--relay NAME]         # stop admitting one; push again to make it take effect
auu card push [--listed] [--knocks]                # sign your card and push it: whether the relay may list you, and whether you take knocks
auu card clear                                     # a card that says neither: not listed, no knocks
auu card show [--json]                             # what each relay holds for you, verified with your own key
```

Relays, anchors and certificates:

```
auu relay add URL [--name NAME] [--anchor HASH] [--default]
auu relay ls [--json]                              # every relay this home knows
auu relay show [NAME] [--json]
auu relay default NAME                             # which relay commands use when none is named
auu relay rename OLD NEW
auu relay rm NAME [--yes]
auu relay couriers [--relay NAME] [--json]         # the relays one accepts forwarded mail from, and which of them you admit
auu anchor [status] [--json]                       # the trust anchor this machine pinned
auu anchor pin HASH                                # pin one and keep the identity
auu anchor forget
auu cert status [--json]                           # this machine's client certificate
auu cert ls [--json]                               # every machine on your identity
auu cert renew                                     # now, rather than at the automatic renewal
```

Sending:

```
auu send --to NAME|self [--subject S] [--channel NAME] [--attach FILE]... TEXT
auu send --to NAME --body-file FILE                # or - to read the body from stdin
auu send --to bob --to carol TEXT                  # a message to several; --to bob,carol is the same
auu send --to ROOM TEXT                            # a message to everyone in a saved room, as if each were named
auu send --to ROOM,carol TEXT                      # a room and names mix, in one value or several --to
auu send --to 'bar!bob' TEXT                       # somebody on a relay yours peers with
auu send --to bob --via bar TEXT                   # the same address, no bang to quote
auu send --resume [--relay R]                      # finish what the outbox holds, on the relay each was opened on: from the relay's partial, or anew; --relay only moves one whose relay this home no longer has
auu outbox [--json]                                # what waits in the outbox to be sent
auu outbox drop ID [PEER] [--json]                 # give one up; PEER says whose, when one id has several waiting
auu reply MESSAGE-ID|THREAD-ID [--all] [--subject S] [--channel NAME] [--attach FILE]... TEXT
```

`send` and `reply` take `--json`. Always give the text: with no body and a
terminal, `--edit` opens an editor and waits, which an agent cannot drive.

An address with `!` in it goes by way of another relay: each name before the
recipient is what *your* relay calls the next one, with no global directory,
so the names come from whoever gave you the address and nothing lists them;
a wrong one comes back as `no neighbour named "bar" on this relay` with
nothing queued. Quote the address, or use `--via`, since `!` is history
expansion in a shell; both at once is refused. An envelope over your
relay's `max_bytes`, never above 64 MiB, is refused `relay returned 413:
envelope too large`, or, far over it, the body-size sentence `request
body larger than this route takes` (under "Sentences that end a
command" below), with nothing queued, by way of a relay as on a post;
the relay's operator sets that cap, not `auu`.
The `id` in `--json` is then a row in your relay's queue, not a message in a
mailbox, and `path` beside it is where it went. A message large enough to
become a stream, which is 64 KiB unless the user has changed it, does not
cross a relay yet: `a large message does not cross a relay yet` — exit 1.
A `--channel` on a path is sent unchecked, since the relay that knows the
recipient's channels is the last hop; a name it refuses comes back later
as a failed message and not as an error from `send`.

Rooms, which are saved lists of recipients under a name:

```
auu room ls [--json]                               # every room and how many are in it: a read, which you may run
auu room show NAME [--json]                        # who is in one: a read, which you may run
auu room create NAME MEMBER...                     # the person's command, since a room decides who they write to; never run it
auu room add NAME MEMBER...                        # the person's command; never run it
auu room rm NAME MEMBER...                         # the person's command; never run it; removing the last member deletes the room
auu room delete NAME [--yes]                       # the person's command; it asks first; never run it
```

A room is kept in `rooms.json` in this home and nowhere else. Nothing of
it is posted, so no relay learns that a room exists. A second machine of
the same identity has its own rooms, as it has its own peer list.

A MEMBER is a peer as `auu send --to` takes one, by name, fingerprint or
short id, or `self`. For somebody on another relay it is `RELAY!NAME`, or
`R1!R2!NAME` with the nearest relay first, and `room show` prints those
relays after `by`. Everybody but `self` must be on the peer list when the
room is made or added to.

A room's name has a peer name's form: letters, digits, `.`, `_` and `-`,
at most 64 bytes. It may not be eight or more hex characters, in either
case, which could be read as the start of a fingerprint. A room is named in
full, in any case, and never by a prefix, and a room and a peer may not
share a name. A home holds at most 256 rooms and a room 1 to 32 members.

`room rm` names a member as the peer list does first. A member who is no
longer on the peer list is named by the short id `room show` prints, or
by eight or more characters from the start of their fingerprint. `room
delete` removes the list alone: the peers in it stay on the peer list. A
`rooms.json` that does not read, or breaks a rule, is said as a damaged
file, exit 5. Until it is fixed, `auu peers add` is refused with exit 1,
the file named, and `auu send` with exit 5, since any name in `--to` might
be a room in it. A `rooms.json` a later auu wrote is not damaged: both
refuse it with exit 1, saying `a later auu wrote it`; auu needs updating.

`auu send --to ROOM` sends to the room's members in the room's order, each
by the relays the room keeps for them, and mixes with names. A name in
`--to` is looked for among the rooms first, whole and in any case, then on
the peer list; a name with `!` in it is an address and never a room.
Everything below is checked before anything is sealed. `--via` beside a
room is refused, and so is one room named twice. The ceiling of 32 and
the relay's `max_recipients` are counted after the rooms are expanded. A
room of one is a message to one, with no list on it. A room with a member
on another relay cannot carry a large message, since a stream does not
cross a relay. Recipients see a message to several and who it went to,
never the room's name.

Reading:

```
auu inbox [--json] [--no-fetch] [--channel NAME]   # fetch from every relay, then list
auu read MESSAGE-ID [--json]
auu extract MESSAGE-ID [--out DIR]                 # save a message's attachments
auu rm MESSAGE-ID... [--local-only | --remote-only] [--json]
auu cursor show [--relay NAME] [--json]
auu cursor reset --relay NAME [--to N] [--yes]
auu queue [--relay NAME] [--json]                  # your mail a relay is still carrying onward
auu wait --thread THREAD-ID [--timeout 10m] [--interval 20s] [--json]
auu watch [--event message|directory]... [--channel NAME]... [--peer NAME]...
          [--timeout 10m] [--interval 20s] [--fetch] [--json]
```

Channels, which are the named sub-mailboxes a sender chooses between:

```
auu channel ls [PEER] [--json]                     # yours, with what each relay holds, or a peer's
auu channel create NAME [--description TEXT] [--not-before T] [--not-after T]
                    [--max-bytes N|none] [--no-streams|--streams] [--no-forwards|--forwards]
auu channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]
                    [--max-bytes N|none] [--no-streams|--streams] [--no-forwards|--forwards]
auu channel close NAME [--at T]
auu channel delete NAME
auu channel keep NAME on|off                       # whether a fetch leaves that channel's mail on the relay
auu channel push                                   # give every relay the directory as it is here
auu channel pull                                   # take the directory a relay holds, from another machine
```

Quarantine, which is mail from a sender who is not on the peer list:

```
auu quarantine ls [--json]
auu quarantine show MESSAGE-ID [--json]
auu quarantine trust MESSAGE-ID                    # the user's decision; it prompts
```

What the fetch kept under `damaged/` because it could not open it:

```
auu damaged ls [--json]                            # what is kept, and why in a word: a read, which you may run
auu damaged reopen RELAY ID | --all [--json]       # open what needed a newer auu: the person's command, since it files mail; never run it
```

`damaged ls` needs no key and changes nothing. `damaged reopen` opens a
message kept as `newer` again with this `auu`, once it is updated, and
files what opens in the inbox or the quarantine as the fetch would have.
It opens that cause alone: any other is refused by name, since no auu can
open it or the check that kept it would keep it again, and `--all` passes
those over. It fetches nothing from the relay. With `auu vouch answer on`
it answers a peer's question after filing, as a fetch does.

Answering a channel for a project, which is an expert host and not
something a messaging agent starts on its own:

```
auu serve [--backlog] [--config FILE] [--json]     # the service: rounds, holding on the relay between them
auu serve --once [--backlog] [--config FILE] [--json]   # one round: fetch, answer, stop
auu serve check [--config FILE]                    # read serve.json and say what it would serve
auu serve ls [--config FILE] [--json]              # what is served, and the threads it is holding
auu serve proxy [--config FILE]                    # the key-holding proxy as its own process, run as another account
```

`serve` answers the channels named in `serve.json` in the home by running
each channel's handler in a git worktree and sending what it printed as the
reply. It is the owner's service, run from a unit file or by hand; see
`docs/serve.md`. Without `--once` it runs until it is stopped, holding on
the relay between rounds. `--backlog` belongs to a first start alone:
without it, mail already in the inbox when serve first runs is left for the
owner.

A `proxy` section in `serve.json` — `key_file`, and optionally `listen`
(loopback only, default `127.0.0.1:0`) and `upstream` (default
`https://api.anthropic.com`) — is the key-holding proxy: serve reads the
API key once from the file and hands the handler `ANTHROPIC_BASE_URL`
(`http://127.0.0.1:PORT/TOKEN`) and `ANTHROPIC_API_KEY` (the same token),
live for that one run of the handler, and never the key. `auu serve check`
then prints `proxy: key from PATH (N bytes), listen 127.0.0.1:0, upstream
https://api.anthropic.com`, the key's size and nothing else of it, and
refuses by name a missing or empty key file (`proxy: key_file PATH does not
exist; it holds the API key on its first line`), a listen off the host
(`is not a loopback address`), a plain-http upstream off the host (`the key
would cross the network in the clear`), a section naming neither `key_file`
nor `control`, and `key_file` beside `control`. On stderr,
`ANTHROPIC_API_KEY is set in serve's environment and is not passed to the
handler or the hooks; the proxy holds the key, and the line that sets it
can go` means a unit still carries the key; the line can go.

`"proxy": {"control": "/run/auu-proxy/control.sock"}` alone is the split
proxy: `auu serve proxy` running as its own account with its own file,
`/etc/auu-proxy/proxy.json` (`v`, `key_file`, `control`, `listen`,
`upstream`, `allow_uids`, `allow_group`), holding the key where the
expert's account cannot read it and handing serve a token per invocation
over that socket. `check` then says `proxy: control PATH (answering)` or
`(nobody is listening; auu serve will fail each message until it is: ...)`;
a message failing with `the proxy's control socket PATH: ...` is the proxy
down or refusing serve's uid, retried next round, and the proxy's own
journal is where its mints, requests and refusals are.

What this binary is, and the skills it carries:

```
auu version [--json]                               # the version it was built from (--version is the same)
auu skill install --target claude|agents [--force] [--json]   # write these three skills out of the binary
auu skill install --dir DIR [--force] [--json]     # the same under DIR/skills, in place of --target
auu skill ls --target claude|agents [--json]       # which of them the directory holds, and whether they match
auu skill ls --dir DIR [--json]                    # the same for DIR/skills
auu skill show NAME|reference                      # print one, without installing it
```

The three skills are in the binary, so a machine with `auu` alone can have
them: `auu skill install` writes `auu-connect`, `auu-setup` and `auu-relay`,
each with its copy of this reference, under the target's skills directory.
`--target claude` is Claude Code's, `$CLAUDE_CONFIG_DIR/skills`, else
`~/.claude/skills`; `--target agents` is `~/.agents/skills`, which Codex
reads; `--dir DIR` is `DIR/skills` and is refused beside `--target`. Give
the target always: with neither, the command asks at a terminal, and with no
terminal, as in an agent's shell, or with `--json`, it refuses, exit 1,
naming the command for each target with its directory: `where the skills go
was not said, and there is no terminal to ask at; run one of:` (or `--json
does not ask`) and the two commands. It prints a first line, `installed
auu-connect, auu-setup and auu-relay in DIR for Claude Code (auu VERSION)`,
`already installed: ...` when every file was this binary's already, or `not
all installed: ...` when nothing was written and a file was kept; then a
line per file, `NAME/FILE: written`, `replaced`, `already current` or `kept,
differs from this binary's copy; --force replaces it`; and, when something
was written, what makes the agent read it: `restart Claude Code, or start a
new session, for it to see them`, or for agents `start a new Codex session
for it to see them; an agent that reads ~/.agents/skills sees them the same
way`. A kept file — the user's own edit, or an older auu's — is left alone,
exit 1, `PATH differs from this binary's copy; kept. --force replaces it`,
and the other files are still written. `auu skill ls` names the directory on
its first line and says per skill `installed`, `differs` or `absent`, which
is what to run after an upgrade; `differs` means run `auu skill install`
with the same target (and `--force` if the user did not edit it).

Keys under a passphrase:

```
auu passphrase set|change|remove                   # the user runs these; they prompt
auu unlock [--ttl 8h] [--passphrase-file PATH]     # the user runs this in their own terminal: receive scope, reads and does not send
auu unlock --send [--ttl 10m]                      # the passphrase again: send scope for the window, then back to receive; --ttl 0 is until lock
auu lock                                           # drop the keys
auu lock --send                                    # end the send window, keep receive
auu agent start|stop|status [--json]
```

Every command that talks to a relay takes `--relay NAME`. Without it the
relay is `AUU_RELAY`, and then the default from `auu relay default`.
`inbox`, `wait`, `watch`, `allow` and `channel` cover every relay the home
is on unless `--relay` narrows them. `auu COMMAND -h` prints one command's
flags.

The operator's commands, which a messaging agent never runs:

```
auu-admin status [--json]                          # the relay, its limits, its administrators
auu-admin mailboxes ls [--after FP] [--limit N]
auu-admin mailboxes show FP
auu-admin mailboxes rm FP [--yes]                  # destructive: the user's word every time
auu-admin mailboxes purge FP [--yes]               # destructive: the user's word every time
auu-admin blocks ls|add FP --reason TEXT [--yes]|rm FP
auu-admin token issue --note TEXT [--expires 168h | --not-after RFC3339] [--uses N]
                      [--for FP] [--use register|cert] [--anchor HASH|none]
auu-admin token ls [--all]
auu-admin token revoke ID
auu-admin token show TOKEN
auu-admin certs ls [FP] [--all]
auu-admin certs revoke SERIAL [--reason TEXT] [--yes]
auu-admin version | --version
```

Every `auu-admin` command takes `--json` and `--relay NAME|URL`.

```
auu-ca init --name NAME [--dir DIR] [--mldsa 44|65|87] [--json]
auu-ca relay --host NAME|IP [--host ...] --out FILE|- [--dir DIR] [--years 1]
auu-ca kit --host NAME|IP [--host ...] --relay-binary FILE --out FILE
           [--admin LINE|@FILE ...] [--listen :9443] [--registration token]
           [--client-certs off] [--without-bundle] [--years 1] [--dir DIR]
auu-ca show [--dir DIR] [--json]                   # what the authority holds and when it expires
auu-ca passphrase [--dir DIR]
auu-ca version | --version
```

The relay itself is flags rather than subcommands, and answers one of them
without any settings: `auu-relay --version` prints the version it was built
from and the database schema it speaks, as `auu-relay v0.18.0 (schema 13)`;
its `relay starting` log line leads with the same two, `version=` and
`schema=`.

## Exit codes

`auu`:

| code | meaning | what to do |
|------|---------|------------|
| 0 | success | carry on |
| 1 | bad usage, unknown peer, or missing identity | fix the command, or tell the user what is missing; do not retry the same words |
| 2 | could not reach the relay, or it refused | read the sentence: a refusal names what to change, a transport failure may pass, and one retry after a pause is enough |
| 3 | `auu wait` or `auu watch` timed out | nothing arrived; say so and ask whether to wait again |
| 4 | the user's keys are locked, or unlocked only to receive | read the sentence: "locked" means tell them to run `auu unlock` in their own terminal; "unlocked to receive" means tell them to run `auu unlock --send` at their terminal, which lasts ten minutes; then retry; never handle a passphrase |
| 5 | a file in the user's home is damaged or has been altered | stop; tell the person which file the sentence names; do not retry, rephrase, or touch the file |

`auu-admin` uses the same codes, without 3: nothing in it waits.

`auu-ca` has three of its own, and its 2 is not a relay failure, since
`auu-ca` talks to nothing: 0 success, 1 bad usage, 2 anything else that
failed — a wrong passphrase, a directory that is not an authority, a file
it could not write.

## What `--json` gives

Field names are as the code prints them. A field marked *when set* is
absent otherwise.

`auu id --json`: `name`, `fingerprint`, `short`, `suite`, `suite_id`,
`pq_category`, `encrypted`, `locked`, `until` (when set), `scope`
(`receive` or `send`, when unlocked), `send_expires` (when send scope has
an end), `relays`, `relay_name` (when set), `relay`, `export_line`.

`auu peers ls --json`: a list of `name`, `fingerprint`, `short`, `suite`,
`suite_id`, `pq_category`.

`auu lookup --json`: `fingerprint`, `short`, `name`, `suite`, `suite_id`,
`pq_category`, `registered` (when set), `known_as` (when set),
`export_line`, `registration` (the relay's mode: `open`, `token` or
`closed`, which is what the name on the relay rests on).

`auu allow show --json`: a list, one per relay, of `relay`, `state`
(`signed`, `none` or `broken`), `issued` (when set),
`senders` — each `fingerprint` and `name` (when the peer list knows them)
— and `error` (when broken). A broken pair exits 1.

`auu listed --json`: `relay`, `registration` (`open`, `token` or
`closed`: what a name here rests on), `entries` — each `fingerprint`,
`short`, `name` (the name on the owner's card, their own claim),
`suite`, `known_as` (when on the peer list: the local name, or `self`) —
and `dropped`, how many entries the relay served that did not verify and
were left out.

`auu knock --json`: `relay`, `fingerprint`, `short`, `claimed_name` (the
name they published, their own claim), `known_as` (the local name this
machine now uses for them), `id`, `thread`, `relay_id`, `text` and
`allow_pushed` (whether your allow list was pushed to that relay after
the knock, which happens when this machine has pushed one there before).

`auu card show --json`: a list, one per relay, of `relay`, `state`
(`signed`, `none` or `broken`), `issued` and `name` (when signed),
`listed`, `knocks`, and `error` (when broken). A broken pair exits 1.

`auu send --json` and `auu reply --json`: `id`, `thread`, `to`, `to_name`,
`relay_id`, `bytes`, `in_reply_to` (when set), `kind` (`envelope` or
`stream`), `chunks` and `chunk_size` (a stream only, and once for a
stream to several, the same for every copy), `channel` (when not
default). `bytes` is a stream's payload, for each copy of one to several. `to` and `to_name` are present exactly when the message went to
one; a message to several has `recipients` in their place, a list of
`fingerprint`, `name`, `path` (when by one), and `relay_id` for a copy the
relay took, or `code` and `error` for one it refused, and `waiting` true
for a copy left in the outbox because the relay refused the sender rather
than the copy, with that refusal's `code` and `error` beside it.
A send to several exits 2 when any copy was not sent, and `auu send
--resume` finishes what waits. A message to several that would be a stream
goes as one stream to each, and a stream copy the relay refuses waits in
the outbox, the whole payload on disk, until `--resume` or `auu outbox
drop ID PEER`.

`auu serve --json`: one object of `answered`, `failed` and `skipped`, each
a list of `id`, `channel` and `thread`. A message in `failed` is tried
again on the next round until the channel's `retries` run out. Under
`--once` the object is always printed; running long, one is printed on its
own line for each round that did something, and nothing for a quiet one.

`auu serve ls --json`: `channels`, each `name`, `dir`, `mode`, `worktree`
(a read-only channel's own, when it has one) and `threads`, each `thread`,
`turns`, `last` and `worktree` (a side-copy thread's own).

`auu inbox --json`: `fetch` with `delivered`, `quarantined`, `unreadable`,
`kept`, `duplicate` (a message already held here arriving a second time
while the relay still has the first, which a resent copy can be:
acknowledged, not delivered again), `newer` (when set: the critical section
each stream left waiting on the relay for a newer auu carries),
`channels_gone` (when set) and `more` (when set: a relay listed more than
this fetch took, past what it held when the fetch began or past the 64
pages a fetch asks, and the next fetch takes the rest); `relays`, a list
of `relay`, `url`, the same fetch counts, `more` among them, `queued`
(what that relay still holds), `first` and `last` (the lowest and highest
message ids it holds for you, both 0 when it holds nothing), `allow` (the
state of your allow list there: `signed`, `none` or `broken`), `card` (the
state of your card there, the same three words), `directory` (the state
of your channel directory there, the same three words again; `broken`
means posts to your named channels are refused until the user runs `auu
channel push`), `outbound` (when that relay forwards and
holds anything of yours: the queue's own rows, as `auu queue --json` gives
them without `relay`, which the entry around them already names) and
`error` (when set); and `messages`, each `id`, `thread`, `in_reply_to`
(when set), `type`, `subject`, `from`, `from_name`, `time` (the sender's
clock), `received` (the relay's), `arrived` (when it arrived on this
machine, or for a sent record when the copy was written here, by its clock,
which orders the list; for an inbox record an earlier release kept, it is
that record's `received`, or when its file was last written if that
`received` cannot be written back), `read`, `box`, `thread_subject` (only
where the whole message is printed: the subject the thread was opened
with, which is `subject` unless the message was given one of its own),
`text` (only where the whole message is printed), `attachments` of `name`,
`media`, `size`, `sha256`, `channel`, `via` (when the message came through
another relay: the relays it crossed, nearest the sender first, joined by
`!`), `on_relay` (when set), `payload_on_relay` (when set), `newer` (when
set: a stream waiting on the relay for a newer auu, by its critical section,
with nothing of what it carries beside it), `ignored_sections` (when set:
the sections this build does not read on a message, or on a stream's
manifest, kept with the message up to 16 KiB each: one it does not know, and
one it knows only on another path, as `recipient-count`, which it
reads on a request alone, and `max-recipients` and `channel-max-bytes`,
which it reads on an answer alone; a section name is known on the paths
that read it and held as an unknown one elsewhere, so one of those marked
critical on a message
needs a newer auu as an unknown critical one does; a message an earlier
release kept with such a section over 16 KiB still loads, and the cap holds
what is fetched from now on) and `dropped_sections` (when set: how many
such sections were over 16 KiB and not kept), and `vouch` (on a message of
type `vouch` alone: `counts`, and when it does not, `why`; when it does,
`voucher` and `subject` (fingerprints), `name` (the voucher's label for the
subject, a suggestion and never a label here), `issued`, `known_as` (when
the subject is already a peer: your name for them) and `you` (when the vouch
is for the user)), and
`ask` (on a message of type `vouch-ask` alone: `about`, the fingerprint
asked about, `known`, whether the user holds it, and `known_as`, their name
for it when they do).

`auu queue --json`: a list, each `id` (a row in that relay's queue, not a
message in a mailbox), `neighbour` (the relay it goes to next, by your
relay's name for it), `path` (what is left of the address after that, when
any), `state` (`waiting`, `handed` or `final`), `tries`, `last_try` (absent
on a row not yet offered), `next_try`, `gives_up`, `code` and `said` (both
on a `final` row: why it will not be delivered, and the sentence the hop
that refused gave with its name in front) and `relay` (which of your relays
holds it). A relay that forwards nothing is skipped with a warning on
stderr, since there is nowhere on it for anything to wait.

`auu read --json` and `auu quarantine ls --json` print that same message
shape: `read` one message with `text` and `thread_subject`, `quarantine ls`
a list without either. `read`, `wait` and `quarantine show` also carry
`room`, when set: the name of this machine's saved room whose members,
`self` left out, are exactly the message's other people. Those are the
sender and the recipients, the reader left out, or the recipients of a
message the user sent. Two such rooms name the first in the file. It
prints as a `room:` line after the `to:` list. `inbox` and `quarantine
ls` carry no `room`. A message to several carries `recipients`, everybody
it went to in its sender's order, each `fingerprint` and `name` (the name
on this machine's peer list, absent for somebody not on it, the reader's
own for the reader). A peer on v0.15.0 reads a message to several as one
from the sender to them alone: their `auu read --json` names `recipients` in
`ignored_sections`, and their `auu reply` reaches the sender alone, so an
answer from one recipient that the others never see is what that looks
like. A message you sent to several carries `copies`, one
per recipient: `fingerprint`, `name`, `path` (when by one), and `relay_id`
once the relay has it, or `code` and `error` when it refused it, and
`dropped` true for one given up with `auu outbox drop`. A reply given a subject of its own carries it in
`subject`, and the thread's in `thread_subject`. A knock carries
`claimed_name` beside `from_name`: the name its sender called themselves,
their own claim, where `from_name` is what this machine calls them, which
is empty until somebody accepts one. A knock that carries vouches carries
`vouches`: `by`, the user's own names for the vouchers they hold whose vouch
counts, `not_verifying`, those whose does not, and `unknown`, how many are
from people the user does not hold. Report it; it changes nothing about who
decides.

`auu wait --json`: `found`, `message` (when found, the message shape),
`waited`.

`auu watch --json`: `events` and `waited`. A message event is `type`
(`message`), `relay`, `channel`, `kind`, `size`, `id`, `received`,
`messages` (with `--fetch`) and `fetch` (with `--fetch`, the inbox's fetch
counts). A directory event is `type` (`directory`), `relay`, `peer`,
`issued`, `added`, `removed`, `updated`, `channels`.

`auu channel ls --json`: `peer` and `fingerprint` (a peer's listing),
`directory`, `issued` (when set), `channels` of `name`, `description`,
`not_before` and `not_after` (when set), `open`, `why` (when set),
`max_bytes`, `no_streams` and `no_forwards` (when the channel has the
rule) and `keep` (your own listing only), and `relays` of `name`, `state` (`same`,
`older`, `newer`, `none`, `unreachable`, `untrusted`), `issued` (when
set), `queued` (a map of channel to count) and `error` (when set).

`auu rm --json`: a list of `id`, `relay` (when one was involved),
`removed_relay`, `removed_local`.

`auu room ls --json`: `rooms`, a list in the order the rooms were made,
each `name`, `members` — each `fingerprint`, `name` (the peer list's name
for them, `you` for this identity, empty for somebody no longer on the
peer list), `via` (when set: the relays to go by, nearest first, joined by
`!`) and `problem` (when set: `not on your peer list`) — and `problem`
(when set: `a peer is named X too`). `auu room show --json`: one such
room.

`auu damaged ls --json`: a list, oldest first, of `relay`, `id` (the
relay's id for the message), `received`, `size` (the kept bytes on this
disk), `cause` (the record's, such as `malformed` or `newer: section
"S"`; empty for a keep cut off before its record was written, or one beside a
record that does not read) and
`section` (when the cause is `newer`: the section's name). A file under
`damaged/` that is not a kept message is not listed, and stderr says
`warning: PATH is not a kept message and is not listed`.

`auu damaged reopen --json`: a list, one per message, of `relay`, `id`,
`outcome` (`filed`, `already held`, `still newer`, `collided` or `left`),
`box` (when filed: `inbox` or `quarantine`), `unchecked` (when set: the
checks against the relay's listing that could not run, because a record
an earlier release wrote does not say what the listing said) and `detail`
(when set: `section "S"` for one still newer, or why it was left). What
the vouch keeping and the question answering print goes to stderr under
`--json`.

`auu cursor show --json`: a list of `relay`, `cursor` (absent when the
file will not read, with `cursor_error` saying why), and `first`, `last`
and `queued` as the relay said them, absent when it could not be asked,
with `error` saying why.

`auu relay ls --json` and `auu relay show --json`: `name`, `url`, `added`,
`default`, `registered`, `anchor` and `anchor_expires` (when set),
`server_intermediate` and `server_intermediate_issued` (when set),
`cert_serial`, `cert_label` and `cert_expires` (when set); `relay show`
alone asks the relay and adds `registration` (`open`, `token` or
`closed`) or, when it could not be asked, `registration_error`.

`auu cert status --json`: `relay_name`, `relay`, `serial`, `label`,
`mldsa`, `not_before`, `not_after`, `renews_after`, `ca_fingerprint` (each
when set) and `present`.

`auu cert ls --json`: the relay's own list — `serial`, `fp` (when set),
`label`, `spki`, `not_before`, `not_after`, `revoked`, `reason` (when set),
`current` (when set).

`auu agent status --json`: `running`, `locked`, `until` (when set), `scope`
(`receive` or `send`, when unlocked), `send_expires` (when send scope has
an end), `keys`, `socket`.

`auu skill install --json`: `target` (`claude`, `agents`, or `dir` for
`--dir`), `dir`, `version`, and `skills`, a list of every file written or
looked at: `name` (the skill), `path`, and `state` (`new`, `updated`,
`unchanged` or `kept`). `auu skill ls --json`: `target`, `dir`, `version`,
and `skills` of `name`, `path` (the skill's directory) and `state`
(`installed`, `differs` or `absent`). `--json` needs the target given, since
it never asks.

`auu version --json`: `version`, and `skills`, the names of the skills the
binary carries. The version is the one the binary was built from — a tag for
a `go install …@vX` build, what version control says for a build from a
clone, and the word `unknown` for a binary built from a copied tree with no
repository behind it. Working from a clone of the repository instead? See
`docs/install-from-clone.md`. `auu-admin version`,
`auu-ca version` and `auu-relay --version` say the same in plain text, the
relay's with its schema.

## Sentences that end a command

A refused send names what to change, and nothing was queued:

- `X is not registered on RELAY` — they have no mailbox there; the sentence
  says where else this home has seen them.
- `X has no channel "y"; their channels are:` with the list — the name is
  not one they publish.
- `X's mailbox has the one channel, default; drop --channel`.
- `X has removed their default channel; choose one with --channel:`.
- `channel "y" is not open: opens T` or `closed T` — outside its period;
  T is UTC, followed by `(T here)` in the user's zone when that differs.
- `channel "y" takes no streams` — the channel's owner refuses streams to
  it; send the content inline, or to another channel.
- `channel "y" takes at most N bytes on the wire; this message is M` —
  the channel's owner caps its size; send less, or to another channel.
  Both are exit 2, and the list of a recipient's channels shows each
  channel's rules after its state.
- `channel "y" takes no mail by way of another relay` — comes back in
  `auu queue` as refused, not as an answer: the channel takes no
  forwarded mail.
- `FILE changed while it was being sent; send it again` — an attachment
  sent as a stream changed between its hashing and its sealing; nothing was
  uploaded and nothing is left in the outbox. Send it again once it is
  settled.
- `sender is not on the recipient's allow list` — they have not admitted
  you; ask them to add you and run `auu allow push`.
- `X's mailbox on the relay is full; they need to run 'auu rm' to make
  room` — theirs to clear, not something to retry.
- `ROOM is a room, which carries its own addresses; send to it without
  --via, and change a member's relays with auu room rm ROOM NAME and auu
  room add ROOM 'RELAY!NAME'` — exit 1; drop `--via`. A member's relays
  are the person's to change.
- `the room ROOM is named twice; name it once` — exit 1; name it once.
- `the room NAME holds SHORT, who is not on your peer list, so nothing was
  sent; remove them with auu room rm NAME SHORT, or add them again with
  auu peers add` — exit 1; which of the two is the person's decision.
- `X (SHORT) is in the room NAME and named as "Y"; name each once`, the
  two sources in the order given on the command line, or `… is in the
  room A and in the room B; …` — exit 1; somebody in a room and named
  too, or in two rooms. Name each once: drop the name, or send to the
  rooms in two messages. Two names for one person are still `"X" and
  "Y" are the same recipient, SHORT; name each once`.
- `NAME is a room's name and your peer SHORT's too, so it names nobody for
  certain; one of the two must go: auu room delete, or auu peers rm` —
  exit 1; the person decides which goes.
- `N recipients once the room NAME is counted; a message may go to at most
  32` (or `the rooms A, B are counted`) — exit 1; the room expanded past
  the protocol's ceiling.
- `N recipients once the room NAME is counted; RELAY takes at most M in one
  message (its max_recipients)` — exit 1; the room expanded past what the
  relay takes, sixteen by default. Split the message, or the person asks
  the relay's operator.
- `a large message does not cross a relay yet, and X is reached by RELAY;
  send them a smaller message on its own` — exit 1; a room, or a list,
  with a member on another relay, sending a message large enough to be a
  stream.
- `--all answers everyone through the relay the message came by, and
  takes no --to or --via; to reach somebody by other relays, send a new
  message to them or to a room, which carries an address for each
  person` — exit 1; drop `--to` and `--via`, or send a new message.
- `malformed token: issuer is not a fingerprint; nothing was described` (or
  another field) — a pasted token whose claims are not the shape of a
  token's; `auu enrol`, `auu token show` and `auu-admin token show` check
  the shape before they describe anything. Ask the issuer for the token
  again.
- `--thread "T" is not a message id (32 lowercase hex characters); a thread
  id is the thread that auu send printed or auu read shows` — a thread is
  named by the `thread` a `send` or `read` reported, never by a name of
  your own; `--reply-to` is held to the same shape. A thread on an expert
  is the conversation of the peer who opened it: `auu serve` leaves
  anybody else's message on it unanswered.
- `message: subject contains U+000A, a control character; a subject is one
  line`, `message: text contains U+001B, a control character`, or
  `attachment "NAME": name contains U+202E, a format character` — a
  message is prose: a subject is one line, and none of the three may carry
  a character a terminal would obey (the text may hold line breaks and
  tabs). Remove the character; nothing was sent.
- `attachment "NAME": NUL is a device name on Windows, so the name is
  refused for every receiver`, `name ends in a dot or a space, which
  Windows strips, ...`, `name begins with a dot, which hides the file
  where it is written, ...`, `name must not contain '?', which Windows
  forbids in a file name, ...` or `name is N bytes, over 200` — the
  sender's rule is the name a receiver would write unchanged: a receiver
  writes every attachment under a safe form of its name (the base name,
  forbidden characters made `_`, trailing dots and spaces trimmed, a
  leading dot made `_`, a device stem prefixed, cut to 200 bytes) and
  never depends on the sender for it, and a sender may not ship a name
  the receiver would change. Rename the file (`con`, `prn`, `aux`, `nul`,
  `com0`–`com9` and `lpt0`–`lpt9`, their superscript forms too, with any
  extension are devices on Windows). Nothing was sent.
- `PATH/serve.json: channel "bugs": channels "Bugs" and "bugs" are one
  directory where case does not count; rename one` — from `auu serve check` or at
  start: each channel is a directory under the serve directory, and two
  names that fold to one would share it on macOS or Windows.
- `"X" is not a token id (32 lowercase hex characters); list them with:
  auu-admin token ls --all` — `auu-admin token revoke` takes the id as
  `token ls` prints it, whole; nothing was sent to the relay.
- `request body larger than this route takes: at most N bytes` (a `413`),
  with `; send the document compact, without indentation` on `allow push`
  or `channel push` — the relay reads every body under its route's cap and
  refuses one over it before reading a byte: an envelope is bounded by the
  relay's `max_bytes`, never above 64 MiB, plus 64 KiB, a signed allow
  list or channel directory by 1 MiB (room enough for the largest either
  can be, as `auu` sends it), and any other request by 64 KiB. From `auu`
  itself the body was under the cap; a `413` means another client, or an
  indented document. `431 Request Header Fields Too Large` is the relay's
  32 KiB header cap, which nothing `auu` sends approaches. On every route
  under `/v1/mailbox/`, on `/v1/forward` and `/v1/forward/failed` and on
  the admin routes the refusal comes before the signature is checked, so
  it is charged as a refused signature is, to the source address's
  `unauthenticated_per_minute`, and answered `429` once that is spent; a
  body whose read failed there is charged the same way. The admin routes
  read the body before they look up the administrator, so there it is the
  same answer for every fingerprint.
- `a request to an admin route declares its body's length` (a `411`) —
  the admin routes refuse a body with no declared length, a chunked one,
  before the administrator is looked up, alike for every caller and
  charged as a refused signature is; one declared over the cap is the
  `413` above, and the rest is read whole, at most 64 KiB, so every byte
  is bounded and read alike before the administrator is known. `auu-admin`
  always declares a length, so nothing of ours meets it; a `411` means
  another client.
- `the directory is N bytes; at most 524288, so send it compact` (or `the
  allow list is ... at most 131072`, or `the card is ... at most 512`) —
  the signed document's own cap, which is not the body's: it is the bytes
  the owner signed, checked before the signature at the push and at every
  reading, and `auu` runs it before it sends one. What `auu` signs is
  never over it; a document that is came from another tool that indented
  it, and the answer is to send it compact.
- `the directory is N bytes as sent, over the relay's cap of 1048576;
  nothing was sent` (or `the allow list is ...`) — `auu` holds the two
  signed documents to the relay's cap before sending; what it signs
  itself always fits, so this is a document another tool indented.
- `the relay stopped taking the upload: no byte was read for 60 seconds`
  on a send, or `the relay stopped sending the stream: no byte arrived for
  60 seconds` on a fetch — the link went quiet for sixty seconds; the
  relay itself cuts an upload slower than a hunk of 64 KiB every ten
  seconds, 6.4 KiB a second, and the next attempt asks the relay where its
  copy ends (`auu send --resume`), the next fetch resumes the download by
  range.
- `warning: the relay asked for a wait of Ns before the first attempt,
  longer than the 10s an opened upload waits; it is opened again after
  the wait` — an opened upload goes ten seconds after its open unless an
  attempt has started, so `auu` lets it go, waits, and opens it again
  once, an open charged as any open is and refused when the hour's budget
  is spent; a second such wait lets that one go too and stops the send
  with the copy in the outbox for `auu send --resume`.
- `malformed answer from the relay at URL: in ANSWER, FIELD is not ...;
  nothing of the answer was used` — the relay's answer lacks a field every
  relay sends, or carries one outside its shape; nothing on the wire is
  from before, so `auu` refuses the answer whole rather than reading the
  absence as an older relay. What is at URL is not this relay, or is
  damaged; its operator looks.
- `answer over the hold: malformed answer from the relay at URL: in the
  answer, the body is not under N bytes, the most this route holds;
  nothing of the answer was used` (exit 2 with `--relay`, or when every
  relay failed; otherwise `auu: NAME could not be reached: …` and the
  fetch goes on to the other relays), from a fetch (`auu inbox`,
  `auu watch`, `auu serve`; a watch that ends on it puts the relay's name
  before it) with N twice the relay's `max_bytes` plus 65536 and at most
  134283264 (128 MiB and 64 KiB) — one message in the mailbox listing is
  over what `auu` holds of a page. When the hold is at its ceiling `auu`
  has already asked for fewer rows, down to one, so this is a row over the
  hold whatever the page, stored before the relay's upgrade, on a relay
  not yet upgraded, or under a larger `max_bytes` than the relay says now,
  since a relay of this release stores no inline row over 64 MiB. It is
  the relay's, not anything on this machine; nothing of it is acknowledged
  or kept, and every fetch from that relay stops at it, a transport
  failure on that relay alone with the user's other relays still fetched,
  until it goes or the cursor is moved past it. The recovery that ends it
  is the relay's operator's: `auu-admin mailboxes purge FP` discards all
  the mailbox's queued mail, not the one message, so the person asks the
  operator and agrees to that loss first. In the meantime
  `auu cursor reset --relay NAME --to ID`, ID that message's relay id
  (`auu cursor show` gives it as the relay's lowest number when nothing
  before it is still there), loses that message alone and lets the mail
  after it through, at a cost: the row stays on the relay, so until the
  operator removes it every fetch from that relay ends at exit 5 with
  `1 message is waiting on RELAY before this machine's cursor`, an
  `auu inbox` across several relays stops there without fetching the ones
  after it, and `auu watch` stops watching that relay, and ends when it is
  the only one. That sentence's advice, to reset the cursor to the
  beginning, leads straight back to the row. The step is the person's to
  choose, and the purge is still needed after it. The same sentence from
  any other route is the entry above.
- `malformed answer from the relay at URL: in the answer to a range
  request (bytes N-M or N-), ... is not the range asked for; a relay, or a proxy
  between, that does not honour a range is a transport failure, and the
  stream waits on the relay for the next fetch; nothing of the answer was
  used` (exit 2) — a fetch of a large
  message asked for part of it and got something else, often the whole
  blob from a proxy or cache that strips `Range`. Nothing is kept as
  damaged and nothing is acknowledged; the fetch from that relay stops
  there, and the stream and everything after it stay on the relay. A
  fetch through a path that honours ranges delivers it.
- `malformed answer from the relay at URL: in the listing, id is not
  above the id asked after and above the row before it, in the order the
  relay promised; nothing of the answer was used` (exit 2) — a page of
  the mailbox listing repeated an id or went back. A relay lists ids in
  ascending order, each above the `after` the fetch asked for; a page
  that does not is refused whole, nothing of it is acknowledged or kept,
  and the mail stays on the relay. What is at URL is not this relay, or
  is damaged; its operator looks.
- `malformed answer: the relay at URL answered METHOD PATH in a shape this
  build cannot read: ...` — the answer carries a field this `auu` does not
  know outside its `sections`; the same advice as the line above.
- `... answered METHOD PATH with a section it must not be read without
  (section "S"); update auu` — the relay is newer than this `auu` and says
  something it must understand; the user updates auu. Exit 2.
- `the relay at URL refused METHOD PATH (STATUS) in words this build cannot
  read` — a refusal whose sentence this `auu` cannot read; the status is
  what is known. Updating auu reads it.
- `relay returned 400: this relay (wire level N) does not know section "S",
  which this request must not be read without; the relay needs a newer
  auu` — this `auu` is newer than the relay and the request needs
  something the relay cannot read. The relay's operator updates it; the
  user waits or uses another relay. A message forwarded through a relay
  that refuses this way comes back as undeliverable in the same words.
  N is the relay's `wire_level`, which its health answer carries: 1 from
  v0.15.0, still 1 in v0.16.0 and v0.17.0, and 2 from v0.18.0, rising when a
  relay can do something new, and required, so a health answer without
  it is refused as malformed. A relay on v0.15.0 serves a v0.16.0 or
  later `auu` in full; its health answer has no `max-recipients`
  section, so a message to several there is held to 32.
- `the relay at URL refused METHOD PATH (STATUS) in an error body without
  its "code"`, or `with an error code that is not one` — the relay is
  older than this `auu`, or what is at URL is not a relay of this
  protocol; the status is what is known.

Anywhere:

- `your identity is locked: run 'auu unlock' in your own terminal` — exit
  4. The user runs it; you never handle the passphrase.
- `the agent is unlocked to receive; run 'auu unlock --send' at a terminal
  to send for the next 10 minutes` — exit 4 too: the keys are unlocked,
  but only to read, and this command originates. The user runs it; same
  rule. `auu serve` says it in its own words, naming `auu unlock --send
  --ttl 0`, since an expert sends until it is locked.
- A damaged file is always the same shape: the path, what is wrong with it,
  Go's reason in brackets when there is one, and what to do — exit 5. Stop
  and name the file.
- `1 message is waiting on RELAY before this machine's cursor; run 'auu
  cursor reset --relay RELAY' to fetch from the beginning` (`N messages
  are` for more than one) — the home was copied or its cursor edited; the
  user decides, and `auu cursor reset` is theirs to run. A cursor above
  everything the relay holds is not this: the fetch resets it itself and
  says so on stderr, `RELAY: this machine's cursor was N and the relay's
  mail is numbered F to L, so the cursor was reset …`, which is worth
  reporting and needs nothing.
- `nothing happened in 10m0s` — a `watch` that timed out, exit 3.
- `no reply on thread T after 10m0s` — a `wait` that timed out, exit 3.

On stderr while `auu inbox` fetches, for a message from a newer build:

- `warning: relay message N from NAME needs a newer auu (section "S") and
  was kept as PATH; update auu and open it with auu damaged reopen RELAY
  N`: a message with a critical section this build does not know, from a
  peer by name or from `an unknown sender, FP16`; the user updates auu and
  runs the reopen, and nobody resends.

And on standard output: `N stream(s) wait on the relay for a newer auu
(section "S"); update auu to fetch them`, and `N message(s) kept under DIR
need a newer auu; update auu and open them with auu damaged reopen --all`,
every run until they are reopened or removed. `auu read`, `auu reply` and
the quarantine's `show` and `trust` answer a waiting stream with `message
ID waits on the relay for a newer auu (section "S"); update auu to fetch
it`. `trust`, which the person runs, refuses a stream whose manifest on
the relay differs from the quarantined record in sender, id or channel
with `ID: the stream on the relay is not the one that was quarantined;
nothing was delivered and the record is as it was`, the record left in
the quarantine. One whose manifest disagrees with the size the relay
listed when it was quarantined is kept under `damaged/` with the fetch's
warning, acknowledged and taken out of the quarantine, settled with exit 0,
with `ID: its manifest says the stream is N bytes on the wire and the
relay listed M; it was settled as damaged and acknowledged, and nobody
was added`. One whose manifest verifies but whose payload will not open,
because it does not decrypt or fails its digest, or whose relay says the
range asked for lies beyond its stored file, is settled the same way,
exit 0, with `ID: its payload will not open; it was settled
as damaged and acknowledged, and nobody was added`. One whose copy the
relay has dropped, answering that the body is gone, is not settled: exit
2, with `ID: its body is no longer on the relay; ask the sender to send
it again`, nothing kept or acknowledged, the record left in the
quarantine. A dropped connection while the payload comes is still a
transport failure, exit 2, the record left in the quarantine. ID is the start of the message's id. None of these adds
anybody, since `trust` adds the sender only once the message is delivered.

On stderr while `auu inbox` fetches, once for a relay in a run; the exit
code is the run's own, 0 when nothing else failed:

- `RELAY: this fetch took the 64 pages it asks at most; the rest waits for
  the next fetch` — the fetch asked that relay for its 64 pages, at most
  12,800 messages, and stopped with the cursor saved at the last message
  taken. Nothing is lost: the next `auu inbox` takes the rest, and `auu
  watch` and `auu serve` on their next round. A relay that lists this much
  again and again is worth reporting to its operator. Mail listed past what
  the relay held when the fetch began waits the same way and is not said;
  `more` in `--json` is true in both cases.

From `auu damaged reopen`, which the person runs and you report:

- `RELAY ID: opened and filed in the inbox` (or `the quarantine`), `already
  held, so its kept copy is removed`, `still needs a newer auu (section
  "S") and is left where it is`, `its id is held from another sender, so
  it is left where it is`, or why else it was left, `and is left where it
  is` — one line per message, exit 0 whatever each line says. A line that
  ends `its record does not say the kind it was listed under or the
  channel it was listed under, so that check could not run` is a record an
  earlier release wrote; report it.
- `RELAY ID was kept with the cause "CAUSE", which is never reopened;
  only a message kept as needing a newer auu is` — exit 1. For one that
  did not decrypt or was malformed, the sender is who to ask.
- `RELAY ID is bytes kept with no record, a keep cut off before its record
  was written, which is never reopened; only a message kept as needing a
  newer auu is` — exit 1.
- `RELAY ID is kept beside a record that does not read (REASON), which is
  never reopened; only a message kept as needing a newer auu is` — exit 1.
- `nothing is kept for RELAY ID; auu damaged ls lists what is` — exit 1.
- A line beginning `another auu is fetching from RELAY; try again in a
  moment` — exit 2, after a minute's wait for that fetch; one retry later
  is enough. `auu quarantine trust` and `auu rm` say it too, with nothing
  of that message changed.
- `N reopened and filed before the key locked; the rest are where they
  were` on stderr beside exit 4, or `… before this stopped; …` beside
  exit 2, or exit 1 when a file could not be written — what was filed
  stays filed; the user unlocks, or waits, and runs it again.

From `auu room`:

- `room ls` prints one line a room, `NAME N member(s)`, with `; K not on
  your peer list` and `; a peer is named X too` when they apply, or `no
  rooms; make one with auu room create NAME MEMBER...`. `room show` prints
  `NAME, N member(s)`, then a line per member: the peer list's name for
  them, `you`, or `(not on your peer list)`; then the short id; then `by`
  and the relays, when the member has them.
- `K not on your peer list: remove each with auu room rm, or add them
  again with auu peers add`, and `a peer is named X too: one name means
  one thing, so one of the two must go: auu room delete, or auu peers rm`
  — from `room show`; report them, and the person decides which.
- `room NAME made with N member(s)`, `N added to NAME, which has M
  member(s)`, `removed` and the member's line for each one `room rm`
  removed, then `N removed from NAME, which has M member(s)` or `NAME had
  nobody left and is deleted`, and `room NAME deleted` — what the
  person's command did; report it.
- `delete the room NAME and its list of N member(s)? The peers stay on
  your peer list [y/N]:` — `room delete` asking; anything but `y` or
  `yes` prints `nothing was deleted; NAME is kept` on stderr and exits 1.
- `X is not on your peer list, and a room holds only people this machine
  can seal to; add them with auu peers add first (REASON)` — exit 1; the
  person adds the peer, and only then the member. A name that matches
  more than one peer is refused with which ones it matches instead.
- `X names PEER (SHORT), who is not in NAME; auu room show NAME lists who
  is, by a short id that names them alone`, and `X and Y are the same
  member of NAME; name each once` — from `room rm`, exit 1.
- `there is no room NAME; auu room ls lists them`, `X is not in NAME; auu
  room show NAME lists who is`, `X is already in NAME; name each once`,
  `X is the start of more than one member's fingerprint in NAME; give more
  of it`, `there is a room NAME already; auu room add NAME MEMBER adds to
  it`, `NAME is your peer SHORT's name, and a room and a peer may not share
  one; choose another`, `NAME could be the start of a fingerprint, which
  names a peer; give the room a name with a letter past f in it`, `X
  names relays to reach yourself by; a copy to yourself goes nowhere, so
  name self alone`, `NAME would have N members, and a room holds at most
  32` and `this home has N rooms, the most it holds; auu room delete one
  first` — exit 1, and nothing was changed.

On stderr after the messages of `auu inbox` or `auu wait`, once per run,
about your own allow list on one relay; the exit code is the run's own:

- `your allow list on RELAY is missing, though you pushed one on DATE;
  run auu allow push and tell the relay's operator` — the relay has lost
  what this machine pushed; run the command, and the user tells the
  operator.
- `your allow list on RELAY does not verify, so nobody can post to you
  there; run auu allow push, and if you did not change it, tell the
  relay's operator` — the list on the relay is not what was signed, or has
  no signature at all, and every post to the mailbox is refused until the
  push; if the user did not
  change it, it was edited on the relay's host, which is the operator's
  incident.
- `this relay takes a signed allow list; the request carries no document`
  — a relay refusing an allow request with no signed document in it, which
  no `auu` of this version sends; nothing was stored.

And about your own card there, in the same place and the same way:

- `your card on RELAY is missing, though you pushed one on DATE; run auu
  card push and tell the relay's operator` — the relay has lost what this
  machine pushed; a bare `auu card push` pushes the same card again.
- `your card on RELAY does not verify, so nobody can knock and you are not
  listed there; run auu card push, and if you did not change it, tell the
  relay's operator` — the card on the relay is not what was signed, or has
  no signature at all; until the push the relay lists you to nobody and
  lets no knock through.

Certificates, when a relay requires them:

- `this relay requires a client certificate and this machine's is STATE:
  run 'auu register --token TOKEN' with a token from an administrator`,
  STATE being `missing`, `not accepted`, `not known`, `revoked`, `expired
  T` or `for another identity`. `missing` means this machine holds no
  certificate for the relay that refused, whatever it holds for others,
  and the command names that relay as `--relay NAME` when it is not the
  default.
- `this identity already holds a live certificate on another machine, so
  adding this one needs a certificate token: ask the administrator for one
  issued with '--use cert --for' FINGERPRINT`.
- `client certificate has been revoked` — that machine was revoked by an
  administrator; the user asks them why before anything else.
