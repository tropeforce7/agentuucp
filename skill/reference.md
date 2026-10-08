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
auu send --to 'bar!bob' TEXT                       # somebody on a relay yours peers with
auu send --to bob --via bar TEXT                   # the same address, no bang to quote
auu send --resume                                  # finish what the outbox holds: from the relay's partial, or anew
auu outbox [--json]                                # what waits in the outbox to be sent
auu outbox drop ID [PEER] [--json]                 # give one up; PEER says whose, when one id has several waiting
auu reply MESSAGE-ID|THREAD-ID [--subject S] [--channel NAME] [--attach FILE]... TEXT
```

`send` and `reply` take `--json`. Always give the text: with no body and a
terminal, `--edit` opens an editor and waits, which an agent cannot drive.

An address with `!` in it goes by way of another relay: each name before the
recipient is what *your* relay calls the next one, with no global directory,
so the names come from whoever gave you the address and nothing lists them;
a wrong one comes back as `no neighbour named "bar" on this relay` with
nothing queued. Quote the address, or use `--via`, since `!` is history
expansion in a shell; both at once is refused.
The `id` in `--json` is then a row in your relay's queue, not a message in a
mailbox, and `path` beside it is where it went. A message large enough to
become a stream, which is 64 KiB unless the user has changed it, does not
cross a relay yet — `a large message does not cross a relay yet` — and a `--channel` on a path is sent unchecked, since the relay
that knows the recipient's channels is the last hop; a name it refuses comes
back later as a failed message and not as an error from `send`.

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
auu channel update NAME [--description TEXT] [--not-before T|none] [--not-after T|none]
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
auu skill install [--dir DIR] [--force] [--json]   # write these three skills out of the binary
auu skill ls [--dir DIR] [--json]                  # which of them the directory holds, and whether they match
auu skill show NAME|reference                      # print one, without installing it
```

The three skills are in the binary, so a machine with `auu` alone can have
them: `auu skill install` writes `connect`, `auu-setup` and `auu-relay`,
each with its copy of this reference, under `DIR/skills` — `--dir`, else
`$CLAUDE_CONFIG_DIR`, else `~/.claude` — and ends with `installed connect,
auu-setup and auu-relay in DIR/skills` and `restart Claude Code, or start a
new session, for it to see them`, or `already installed: ...` when every
file was this binary's already. A file that differs from the binary's copy
— the user's own edit, or an older auu's — is left alone and named, exit 1:
`PATH differs from this binary's copy; kept. --force replaces it`; the other
files are still written, and `--force` replaces the differing ones and
says `(updated NAME)`. `auu skill ls` says per skill `installed`, `differs`
or `absent`, which is what to run after an upgrade; `differs` means run
`auu skill install` (and `--force` if the user did not edit it).

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
from and the database schema it speaks, as `auu-relay v0.11.0 (schema 8)`;
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
`stream`), `chunks` and `chunk_size` (a stream only), `channel` (when not
default).

`auu serve --json`: one object of `answered`, `failed` and `skipped`, each
a list of `id`, `channel` and `thread`. A message in `failed` is tried
again on the next round until the channel's `retries` run out. Under
`--once` the object is always printed; running long, one is printed on its
own line for each round that did something, and nothing for a quiet one.

`auu serve ls --json`: `channels`, each `name`, `dir`, `mode`, `worktree`
(a read-only channel's own, when it has one) and `threads`, each `thread`,
`turns`, `last` and `worktree` (a side-copy thread's own).

`auu inbox --json`: `fetch` with `delivered`, `quarantined`, `unreadable`,
`kept`, `newer` (when set: the critical section each stream left waiting on
the relay for a newer auu carries) and `channels_gone` (when set); `relays`, a list of `relay`, `url`,
the same fetch counts, `queued` (what that relay still holds), `first`
and `last` (the lowest and highest message ids it holds for you, both 0
when it holds nothing), `allow`
(the state of your allow list there: `signed`, `none` or
`broken`), `card` (the state of your card there, the same three words),
`directory` (the state of your channel directory there, the same three
words again; `broken` means posts to your named channels are refused
until the user runs `auu channel push`), `outbound` (when that relay
forwards and holds anything of yours: the queue's own rows, as `auu queue
--json` gives them without `relay`, which the entry around them already
names) and `error` (when
set); and `messages`, each `id`, `thread`, `in_reply_to` (when set),
`type`, `subject`, `from`, `from_name`, `time`, `received`, `read`, `box`,
`thread_subject` (only where the whole message is printed: the subject the
thread was opened with, which is `subject` unless the message was given one
of its own), `text` (only where the whole message is printed), `attachments` of `name`,
`media`, `size`, `sha256`, `channel`, `via` (when the message came through
another relay: the relays it crossed, nearest the sender first, joined by
`!`), `on_relay` (when set),
`payload_on_relay` (when set), `newer` (when set: a stream waiting on the
relay for a newer auu, by its critical section, with nothing of what it
carries beside it), `ignored_sections` (when set: the sections this build
did not know, kept with the message) and `dropped_sections` (when set: how
many were too large to keep), and `vouch` (on a message of type `vouch`
alone: `counts`, and when it does not, `why`; when it does, `voucher` and
`subject` (fingerprints), `name` (the voucher's label for the subject, a
suggestion and never a label here), `issued`, `known_as` (when the subject
is already a peer: your name for them) and `you` (when the vouch is for
the user)), and `ask` (on a message of type `vouch-ask` alone: `about`, the
fingerprint asked about, `known`, whether the user holds it, and
`known_as`, their name for it when they do).

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
a list without either. A reply given a subject of its own carries it in
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
`not_before` and `not_after` (when set), `open`, `why` (when set) and
`keep` (your own listing only), and `relays` of `name`, `state` (`same`,
`older`, `newer`, `none`, `unreachable`, `untrusted`), `issued` (when
set), `queued` (a map of channel to count) and `error` (when set).

`auu rm --json`: a list of `id`, `relay` (when one was involved),
`removed_relay`, `removed_local`.

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

`auu skill install --json`: `dir`, and `skills`, a list of every file
written or looked at: `name` (the skill), `path`, and `state` (`new`,
`updated`, `unchanged` or `kept`). `auu skill ls --json`: `dir`, and
`skills` of `name`, `path` (the skill's directory) and `state`
(`installed`, `differs` or `absent`).

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
- `sender is not on the recipient's allow list` — they have not admitted
  you; ask them to add you and run `auu allow push`.
- `X's mailbox on the relay is full; they need to run 'auu rm' to make
  room` — theirs to clear, not something to retry.
- `malformed token: issuer is not a fingerprint; nothing was described` (or
  another field) — a pasted token whose claims are not the shape of a
  token's; `auu enrol`, `auu token show` and `auu-admin token show` check
  the shape before they describe anything. Ask the issuer for the token
  again.
- `--thread "T" is not a message id (32 lowercase hex characters); a thread
  id is the id of the message that opened it` — a thread is named by the
  `thread` a `send` or `inbox` reported, never by a name of your own;
  `--reply-to` is held to the same shape.
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
  or `channel push` — the relay reads every body under its route's cap
  and refuses one over it before reading a byte: an envelope is bounded by
  the relay's `max_bytes` plus 64 KiB, a signed allow list or channel
  directory by 1 MiB (room enough for the largest either can be, as `auu`
  sends it), and any other request by 64 KiB. From `auu` itself the body
  was under the cap; a `413` means another client, or an indented
  document. `431 Request Header Fields Too Large` is the relay's 32 KiB
  header cap, which nothing `auu` sends approaches.
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
  60 seconds` on a fetch — the link went quiet for the relay's stall
  window; a stream has no other clock, and the next attempt asks the relay
  where its copy ends (`auu send --resume`), the next fetch resumes the
  download by range.
- `malformed answer from the relay at URL: in ANSWER, FIELD is not ...;
  nothing of the answer was used` — the relay's answer lacks a field every
  relay sends, or carries one outside its shape; nothing on the wire is
  from before, so `auu` refuses the answer whole rather than reading the
  absence as an older relay. What is at URL is not this relay, or is
  damaged; its operator looks.
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
  v0.15.0, rising when a relay can do something new, and required, so a
  health answer without it is refused as malformed.
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
  was kept as PATH; update auu to read it`: a message with a critical
  section this build does not know, from a peer by name or from `an unknown
  sender, FP16`; the user updates auu, and nobody resends.

And on standard output: `N stream(s) wait on the relay for a newer auu
(section "S"); update auu to fetch them`, and `N message(s) kept under DIR
need a newer auu; update auu to read them`, every run until an updated auu
reads them. `auu read`, `auu reply` and the quarantine's `show` and `trust`
answer a waiting stream with `message ID waits on the relay for a newer auu
(section "S"); update auu to fetch it`.

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
