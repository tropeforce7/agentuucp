# Running a relay

The relay binary, its settings and limits, its certificates, and how it is administered. `deploy-linux.md` is the same relay as a system service on a Linux host, step by step. This is the reference behind it.

## 1. Running a relay

The short way onto a Linux host with systemd is a kit. `auu-ca kit` packs the relay
binary, the settings and administrators for the host, the unit and the
signing bundle into one archive. Its `install.sh` installs the relay as
a system service, or brings one already there up to date with `update`.
[`docs/deploy-linux.md`](deploy-linux.md) has the recipe under *The
short way*, and the long way beside it. By hand, with a bundle from
*Certificates without a public CA* below:

*Listing 1a*
```
auu-relay --listen :9443 --db /var/lib/auu/relay.db --tls-bundle relay-bundle.json
```

A relay serves TLS by default. Started with no bundle and no certificate
it refuses, in one sentence naming `auu-ca init`, `auu-ca relay` and the
one way out. That way out is `--tls-mode off`, which is plain HTTP. It is
for a try on your own machine and not for a relay anybody reaches over a
network. It exists only when written down.

Settings come from three places. They are built-in defaults, then the file
named by `--config`, then the flags actually typed on the command line.
Later ones win. A flag you do not type never overrides the file.

| flag | config key | default |
|---|---|---|
| `--config PATH` | | none, there is no implicit location |
| `--listen ADDR` | `listen` | `:8080` |
| `--db PATH` | `db` | `relay.db` |
| `--messages-dir PATH` | `messages_dir` | `messages/` beside the database |
| `--max-bytes N` | `max_bytes` | 16 MiB, at most 1 GiB; an inline envelope is held to 64 MiB whatever it is |
| `--streams` | `streams` | true |
| `--max-stream-bytes N` | `max_stream_bytes` | 4 GiB, 0 is unlimited |
| `--registration open\|token\|closed` | `registration` | `open`; the health answer carries the word, since it is what a name listed on this relay rests on; `open` refuses to start with `courier.home` set |
| `--public-url URL` | `public_url` | none |
| `--admin-file PATH` | `admin.authorized_file` | none, no administrators |
| `--token-max-age DURATION` | `admin.token_max_age` | `720h` |
| `--courier-home PATH` | `courier.home` | none, this relay dials no other relay; needs `registration` `token` or `closed`; see 1.10 |
| `--courier-file PATH` | `courier.authorized_file` | none, this relay accepts no forwarded mail; see 1.10 |
| `--courier-max-hops N` | `courier.max_hops` | 8, between 1 and 32 |
| `--courier-forward-ttl DURATION` | `courier.forward_ttl` | `72h`, between `1m` and `720h` |
| `--courier-queue-max-bytes N` | `courier.queue_max_bytes` | 1 GiB, 0 is unlimited |
| `--courier-queue-max-messages N` | `courier.queue_max_messages` | 100000 across the relay, at most 100000, 0 is unlimited |
| `--courier-queue-max-messages-per-poster N` | `courier.queue_max_messages_per_poster` | 100, at most 100000, 0 is unlimited |
| `--courier-queue-max-messages-per-courier N` | `courier.queue_max_messages_per_courier` | 10000 for one neighbour, in place of the per-poster count, at most 1000000, 0 is unlimited |
| `--courier-queue-max-bytes-per-poster N` | `courier.queue_max_bytes_per_poster` | 256 MiB, 0 is unlimited |
| `--courier-posts-per-minute N` | `courier.posts_per_minute` | 600, a neighbour's own rate, 0 is unlimited |
| `--courier-reports-per-minute N` | `courier.reports_per_minute` | 60, a neighbour's rate for undeliverables, a tenth of its posting rate; see 1.10, 0 is unlimited |
| `--courier-post-bytes-per-hour N` | `courier.post_bytes_per_hour` | 0, unlimited; see 1.10 |
| `--courier-carried-max-rows N` | `courier.carried_max_rows` | 1000000, 0 is unlimited |
| `--courier-carried-rows-per-poster N` | `courier.carried_rows_per_poster` | a sixteenth of `courier.carried_max_rows`, 62500 at its default, raised to 30 at the default `courier.max_hops` when that is less, and never above a nonzero ceiling; the most one person's hashes may stand at once, a hash costing one for each relay the envelope's path still names; the sustained rate is the share over 1 + H(`courier.max_hops`) each `courier.forward_ttl`; see 1.10, 0 is unlimited |
| `--courier-carried-rows-per-courier N` | `courier.carried_rows_per_courier` | a quarter of `courier.carried_max_rows`, 250000 at its default, raised to 30 at the default `courier.max_hops` when that is less, and never above a nonzero ceiling; the most one neighbour's hashes may stand at once, a hash costing one for each relay the envelope's path still names; the sustained rate is the share over 1 + H(`courier.max_hops`) each `courier.forward_ttl`; see 1.10, 0 is unlimited |
| `--client-certs off\|required` | `client_certs.mode` | `off`; `required` needs `registration` `token` or `closed` |
| `--client-cert-lifetime DURATION` | `client_certs.lifetime` | `8760h`, between `1h` and `87600h` |
| `--tls-mode off\|files` | `tls.mode` | `files`; `off` only when said, see below |
| `--tls-cert PATH` | `tls.cert_file` | none |
| `--tls-key PATH` | `tls.key_file` | none |
| `--tls-bundle PATH` | `tls.bundle` | none; an export from `auu-ca` |
| `--tls-bundle-credential NAME` | `tls.bundle_credential` | none; the same export as a systemd credential, read from `$CREDENTIALS_DIRECTORY` |
| `--limit-requests N` | `limits.requests_per_minute` | 120 |
| `--limit-posts N` | `limits.posts_per_minute` | 30 |
| `--limit-post-bytes N` | `limits.post_bytes_per_hour` | 256 MiB |
| `--limit-unauthenticated N` | `limits.unauthenticated_per_minute` | 30 |
| `--limit-registrations N` | `limits.registrations_per_hour` | 5 |
| `--max-mailboxes N` | `limits.max_mailboxes` | 0, unlimited |
| `--mailbox-max-messages N` | `limits.mailbox_max_messages` | 1000 |
| `--mailbox-max-bytes N` | `limits.mailbox_max_bytes` | 1 GiB |
| `--relay-max-bytes N` | `limits.relay_max_bytes` | 0, unlimited |
| `--max-open-uploads N` | `limits.max_open_uploads` | 4, at most 1000 |
| `--max-upload-opens-per-hour N` | `limits.max_upload_opens_per_hour` | 64 |
| `--max-inflight N` | `limits.max_inflight` | 256 |
| `--max-waiting N` | `limits.max_waiting` | 64 |
| `--knock-max-bytes N` | `limits.knock_max_bytes` | 20480, at most `max_bytes`; 0 is `max_bytes`; never above 64 MiB in force |
| `--max-knocks-waiting N` | `limits.max_knocks_waiting` | 10, at most 1000 |
| `--knocks-per-hour N` | `limits.knocks_per_hour` | 10 |
| `--max-recipients N` | `limits.max_recipients` | 16, at most 32; 0 is 32 |
| `--access-log full\|minimal` | `access_log` | `full` |
| `--print-config` | | print the merged settings and exit |
| `--version` | | print `auu-relay vX (schema N)` and exit; needs no settings |

The TLS mode is `files` unless you set it to `off`. `files` with no bundle
and no certificate is refused at startup, in a sentence that names the two
`auu-ca` commands and the flag. `off` is plain HTTP, logged as such on the
relay's first lines, and exists for a try on one machine. `off` with a
bundle is refused. A bundle is what the relay serves TLS from, and nothing
stands in front of the relay to terminate for it.

The relay's first lines say what it is and how it is set. The `relay
starting` line leads with `version=`, the version the binary was built
from, and `schema=`, the database schema it speaks, then the address, the
TLS mode, the database, and for `files` the certificate and where the
bundle came from. So a journal answers which relay is running without a
shell on the host. `auu-relay --version` answers the same of a binary in
hand.

`tls.bundle` and `tls.bundle_credential` name the same file two ways, and
you give one of them. The first is a path. The second is the name of a
systemd credential. The unit's `LoadCredentialEncrypted=` line unseals the
bundle at service start into a directory only that service can see. The
relay reads it from `$CREDENTIALS_DIRECTORY`, which systemd sets. Started
without that variable, the relay refuses to start and names the directive it
expected. The shipped `docs/systemd/relay.json` uses the credential. See
*Certificates without a public CA* below for why.

`public_url` must name a host the bundle was issued for, one of the `--host`
values given to `auu-ca relay`. Tokens carry it and machines verify the
relay's certificate against it. The certificate is minted for the
bundle's hosts, so a bundle for another host would start a relay nobody can
reach. The relay refuses to start instead, naming both hosts and the
`auu-ca relay` command that issues a bundle for the right one. Names are
compared without regard to case, addresses as addresses.

A path in the settings file that is not absolute is relative to the
directory the settings file is in, not to the directory the relay was
started from. That covers `db`, `messages_dir`, `admin.authorized_file`,
`courier.home`, `courier.authorized_file`, `tls.cert_file`, `tls.key_file`
and `tls.bundle`. `"db": "relay.db"` in
`/etc/auu/relay.json` is `/etc/auu/relay.db` whether systemd or a shell
started the relay. The default when the file names no `db` at all follows
the same rule, `relay.db` and `messages` beside the settings. A path given
as a flag is the shell's, relative to the working directory as any flag is.

The settings file is read strictly, and a file the relay would read two ways
is refused at startup, naming the key. A key the relay does not have is
refused. So is a key in another case than the table's (`"Listen"` for
`listen`), which the JSON reader would otherwise take as that key, and a key
given twice in one object, of which it would keep the last. Nothing may
follow the closing brace but white space.

Use `--print-config` to see exactly what the relay resolved, paths
included. Its output is valid input for `--config`. A relay that peers
with nobody prints no `courier` block, since a block of numbers without
`courier.home` or `courier.authorized_file` is refused (see 1.10).

### 1.1 Where the mail lives

The database holds the bookkeeping. The mail itself is one file per message
beside it.

*Listing 1.1a*
```
/var/lib/auu/
  relay.db                     mailboxes, counters, one row per message with its kind, the three owner-signed documents
  messages/
    tmp/                       writes in progress, swept at startup
    uploads/                   streams still being uploaded
    outbound/                  mail waiting to go on to a neighbouring relay, one file per queued row
    b4/
      b49c…64 hex…/            one directory per recipient
        17                     one message, exactly the bytes that were posted
```

Each message's row has an id the database numbers from 1 and never reuses.
A listing says the lowest and highest ids the mailbox holds, read from those
rows in the same transaction as the page. Nothing new is counted or kept
for it. A client whose cursor is above the highest is told at once, even on
a held listing, and fetches again from the lowest. A database that is
deleted begins its numbering again, which is when that happens to every
client at once. A relay that carries its database forward keeps its
numbering.

So `relay.db` stays small whatever the relay is carrying. A 2 GB message is
four kilobytes of database and a two gigabyte file. A completed upload is
*renamed* into place rather than copied. That is why finishing one is instant
however large it is, and why `messages_dir` must be a single filesystem.

The database also holds, per mailbox, the three documents an owner signs
and pushes — the channel directory in `directories` and `channels`, the
allow list in `allowlists`, and the card in `cards`, each the bytes the
owner signed and the signature over them, verified against the mailbox's
registered key at the push and again wherever the relay acts on one: the
allow list and the directory at every post, and at a stream's open, at
each of its attempts and before its placement, `default` included, and
the card at every knock. The
`channels` rows beside the directory's bytes are the relay's parse at the
push, kept for the administrator's count and for the watch's issue time.
Nothing routes by them, so a row inserted or edited with the database open
changes what `auu-admin` prints and not where a message goes. A
directory whose bytes or signature are edited routes nothing at all: the
mailbox is closed to every post, `default` and the owner's own included,
until they push again, as a mailbox whose allow list does not verify is,
and the owner is told at their next fetch.
Beside a card's bytes sit its issue time and the two words the relay
parsed from it, `listed` and `knocks`, which are for the administrator's
line and decide nothing: an edit to those columns changes what
`auu-admin` prints and not what the relay does, and an edit to the bytes
or the signature makes the row `broken`, which the owner is told of at
their next fetch and repairs with a push, whatever issue time the edit
left. The name on a card is not stored a second time. The relay has no
use for it.

A message row carries its kind, `envelope`, `stream` or `knock`, the word
the route it arrived by gives it and the word every listing says beside
the row. A knock is an envelope a stranger posted to the knock route of a
mailbox whose card, verified at that moment and never read from the
column, says `knocks`. A knock row carries one thing no other row does:
the fingerprint of the knocker, the one the request's signature proved and
never anything the envelope claims. It is there so that a second knock
from the same key replaces the first — which is what makes
`max_knocks_waiting` a count of knockers. It lives exactly as long as the
row: until the owner's fetch acknowledges it, until it is replaced, or
until the mailbox goes. Beside the uploads table it is the only place the
relay records who is sending something. An operator whose users would
rather it did not can say so, and those users push a card that takes no
knocks.

An operator can list all of this, and count it, and delete it. None of it can
be read. Every file is a sealed envelope or a sealed stream.

**Back up the database and the message directory together**, or you will
restore an index pointing at mail that is not there. A relay that finds
one without the other says so at startup and repairs itself towards the
database. Files in a mailbox's directory with no row are removed. `tmp/`,
`uploads/` and `outbound/` are the relay's own and are not read as
mailboxes. Rows with no file are dropped and logged. A stream whose file
has changed length since it was stored is dropped by the same rule when
its recipient asks for it. The log carries the message id and both
lengths. It carries the mailbox only under `access_log: "full"`, since its
owner is the caller. The recipient's `auu inbox` says which message was
damaged on the relay and to ask the sender to send it again, then moves
on. The one case it will not repair is a database that knows no mailbox at
all beside a directory that holds mail, since repairing that would mean
removing every message. The database was lost. The relay refuses to start,
saying so, and naming the two remedies, restoring `relay.db` from a backup
or moving the message directory aside to start empty.

A database at this version's schema is opened as it is. One from schema
11 on, the first kept version, is carried forward: before anything
changes, the relay copies it to the same path with `.before-schema-N`
appended, `N` the version it found, mode 0600, and then takes it one
version at a time, each step and its version number committed together,
so a database is always at some whole version. The journal says so at
the start, naming both versions and the copy. The copy is the way back
to the release before, with that release's binary, and it is yours to
remove once this release has run as you want. The relay never removes
it, and never replaces one: anything already at that path, a copy from an
upgrade you went back from among others, stops the start with nothing
changed until you move it aside or remove it.

Going back costs every message that arrived after the upgrade, since the
copy has no row for it and the release before removes a file no row
claims. A way back that must keep them starts from a backup of the message
directory taken at the same time. It also puts every row back as it was at
the upgrade, and so undoes everything an administrator or a user changed
on the relay since: a mailbox removed since is back with its certificates,
a certificate or a token revoked since is live again, a token spent since
has its uses back, a block added since is gone, and each allow list, card
and directory is the one held at the upgrade, or none. Make those changes
again after going back.

A copy that cannot be made stops the start, naming its path and the
cause, with nothing changed, and a step that fails stops it naming the
step, the version the database is still at and the copy. A database named
in the settings as a `file:` URI is not carried forward. Name it by its
path. A database from
before schema 11 is refused, never read: delete it and the message
directory beside it, and the relay recreates both at the next start,
after which every machine enrolled on it enrols again. The refusal says
so, naming both paths. One from a newer release is refused too, naming
the version it found and the one this relay understands.

### 1.2 Large messages

Above 64 KiB a client stops posting one envelope and uploads a stream. A
stream is an open that reserves the room, then one request per attempt
carrying the sealed bytes from an offset to the end. Three settings govern it:

| setting | what it does |
|---|---|
| `streams` | whether the relay accepts stream uploads at all. Turn it off and an open is refused with a 403 naming this setting |
| `max_stream_bytes` | the largest stream the relay will reserve space for, declared up front and refused before a byte is sent. `0` is unlimited, under a cap of 2^62 bytes no setting lifts |
| `max_bytes` | besides being the largest envelope a post, a forward, delivered here or carried on, a courier's delivery or a knock may carry (never above 64 MiB whatever the setting), the resume threshold: an attempt that stops short after at least this many bytes, when it was the first, leaves a partial the sender may resume once within sixty seconds; one that stops short of it, or a resumed one that stops short, leaves nothing, and the upload and its reservation go with the answer. The relay announces it at the open as `resume_threshold`, with the window as `resume_window`. A listing page follows it too: a page ends before an envelope that would take its inline bytes past `max_bytes`, or past 64 MiB whatever `max_bytes` is, admitting the first whatever its size, so a page's envelopes never exceed that unless the first alone does, which only one stored under a larger earlier `max_bytes`, or before this release, can; the health answer says the setting so a client can size what it holds of a page to this relay, and raising `max_bytes` grows every client's page with it up to 64 MiB, half of the most `auu` holds of a page. Above 64 MiB the setting raises the resume threshold and nothing inline (below the table) |

The windows are not settings. An upload is fed or it goes. One nobody starts
an attempt on goes ten seconds after its open, the start window, and a kept
partial goes sixty seconds after it was kept, the resume window. The open
answer names the resume window, and of the start window only the moment it
ends, its `expires`; a client of this release knows the window, and an older
one meets the 410. Past either, the relay refuses the next attempt with a
410 that says when the upload expired and to open again. It forgets the
upload with the answer, so the reservation ends when it was promised to. The
sender's `send --resume` opens a new upload for the same sealed bytes. An
expired upload nobody touches is swept by the purge that runs every
hundredth request. The purge runs too when a post, an open, a knock or a
courier's delivery is refused `507` because reservations and messages fill
the recipient's quotas or `relay_max_bytes`. When it lets an upload go, the
request asks for the room once more. So these four answer that `507` only
when the room is taken by what still counts. A full disk is refused the same
way, and the purge frees only what kept partials held there. The purge skips
an upload mid-attempt rather than wait behind its sender and returns to it
next time. Bytes that stop coming, or come too slowly, end inside a window
too. An attempt runs under a hunk deadline: ten seconds from its start, set
ten seconds on from the read that completes a whole hunk of 64 KiB since it
last moved, and at no other read. So a transfer of any length finishes while
it keeps a pace of 6.4 KiB a second, and a slower or stalled one is cut and
judged as an attempt that stopped short. A deadline that every byte moved
would let a sender trickle a byte a window and hold its reservation for
ever. The download of a placed stream is served under a stall deadline of
sixty seconds, moved by every write that delivers bytes. So a slow reader is
served to the end and a reader that stops is cut inside the window. The
server's five-minute read and write timeouts stand on every other route.

An upload is held to what admitted it for as long as it lives, not at its
open alone. At the start of every attempt, before a byte of its body is
read, the relay judges again what the open judged: that the sender is on
the recipient's allow list, that the recipient is not a courier's
mailbox, and that the upload's channel exists and is open. It judges them
once more after the last byte and before the stream is placed, under the
upload's lock. A refusal is the answer the open would give, `403` with
the allow list's sentence, or the channel's `404`, or `403`
`channel-closed` with its sentence. The upload goes with it, its partial
and its reservation, and the open's charge stands, as a refused post's
does. So removing a sender from the allow list, or closing a channel,
takes effect at the sender's next attempt on an upload already open and
at any placement after it, never only at its next open. A large stream
runs for hours at the pace, and one whose sender is removed partway
through does not land, nor does an attempt running at the moment of the
removal, which places nothing.

A relay takes a `max_bytes` above 64 MiB, but it holds every inline row
to 64 MiB whatever the setting: a post, a forward, delivered here or
carried on, and a courier's delivery over it are refused `413` with
`envelope too large`, and a knock over it `413` naming
`knock_max_bytes`, a set `knock_max_bytes` above 64 MiB included. A
forward with a path still to go is refused before its neighbour is
looked up and before anything is charged to the carried share, queued
or written, so nothing over the operator's ceiling waits here for a
neighbour to refuse it. Above 64 MiB the setting raises
a stream's resume threshold and nothing else, and the health answer
still says it, with `knock_max_bytes` as it is in force. A courier
carrying a larger row from a relay before this release is refused `413`
too, which it takes as final: the message ends there and its sender is
told which relay refused it and why. `auu` sends at most 16 MiB inline,
so what it sends this relay stores and every client lists. `auu` holds a
listing page to twice `max_bytes` plus 64 KiB, at most 128 MiB and
64 KiB, and a page carries its envelopes as the JSON they were posted
as, so every page this relay builds fits but one whose first row alone
is over that hold. An `auu` asks a relay not yet upgraded, which fills a
page to its whole `max_bytes`, for fewer rows at a time until the page
fits. What is left is a single row over the hold, stored before the
relay's upgrade, on a relay not yet upgraded, or under a larger
`max_bytes` than the relay says now: a relay whose `max_bytes` was
lowered still holds rows stored under the larger setting, and a client
sizes its hold to the figure it says now. Every `auu` that lists the
mailbox refuses it, and each fetch stops at it until the row goes or the
cursor is moved past it. Its owner can step past it with
`auu cursor reset --relay NAME --to ID`, losing that message alone and
letting the mail after it through, but the row stays queued here: until
it goes, every fetch from this relay ends at exit 5 saying the cursor
skips mail, an `auu inbox` across several relays stops here without
fetching the ones after it, and `auu watch` stops watching this relay,
and ends when it is the only one. The recovery that ends it is yours:
`auu-admin mailboxes purge FP` discards every message queued for that
mailbox and keeps the mailbox, so tell the owner first, and purge once
they have stepped past it, or instead of it.

**At the shipped defaults a 2 GB file is refused**, and deliberately so. A
sender's whole `post_bytes_per_hour` budget is 256 MiB and one recipient's
`mailbox_max_bytes` is 1 GiB. Both are per-sender and per-mailbox rather than
per-message. So raising them is a decision about how much of your disk one
person may fill, not about how big a file may be. To allow it, raise those two:

*Listing 1.2a*
```
auu-relay --db /var/lib/auu/relay.db \
  --limit-post-bytes 8589934592 \
  --mailbox-max-bytes 8589934592
```

The refusal names the setting that stopped it, and arrives before any of the
file is uploaded, so nothing is wasted finding out.

### 1.3 Config file

*Listing 1.3a*
```json
{
  "listen": ":9443",
  "db": "/var/lib/auu/relay.db",
  "registration": "token",
  "public_url": "https://relay.example.com:9443",
  "admin": {
    "authorized_file": "/etc/auu/admins",
    "token_max_age": "720h"
  },
  "tls": {
    "mode": "files",
    "bundle_credential": "relay-bundle"
  }
}
```

Every key is optional. An unrecognised key is an error rather than a setting
that silently does nothing. Nothing in the file is secret, but whoever can
write it can change who administers the relay. The relay warns at startup if
it is writable by anyone but its owner.

### 1.4 Limits

One registered peer, one source address, or one runaway agent should not be
able to take the relay away from everybody else. Every limit is a number you
set, and **zero means unlimited**. So a private relay for three people can
switch the lot off.

| setting | what it bounds | default |
|---|---|---|
| `requests_per_minute` | authenticated requests, per identity | 120 |
| `posts_per_minute` | posts, per identity | 30 |
| `post_bytes_per_hour` | posted bytes, per identity: an envelope's size, and a stream's declared size when it is opened, of which an upload with kept bytes is given back the size less them when it goes unplaced, while one that goes holding no byte gives nothing back | 256 MiB |
| `unauthenticated_per_minute` | registrations, key lookups, failed authentications, and bodies refused before their signature is checked (a `413` or `411` for the length, or a read that failed), per source address | 30 |
| `registrations_per_hour` | registrations, per source address | 5 |
| `max_mailboxes` | mailboxes on the relay | unlimited |
| `mailbox_max_messages` | messages queued for one recipient | 1000 |
| `mailbox_max_bytes` | queued bytes for one recipient | 1 GiB |
| `relay_max_bytes` | queued bytes in the mailboxes across the whole relay; mail waiting to go to a neighbouring relay is a second pool, under `courier.queue_max_bytes` | unlimited |
| `max_open_uploads` | uploads one sender may have open at once, across every mailbox it sends to; each is a file and a reservation the relay holds for that sender, so 0, unlimited like the rest, lets one sender hold as many as it likes; at most 1000 | 4 |
| `max_upload_opens_per_hour` | uploads one sender may open in an hour, whatever became of them, refused `429` with a `Retry-After` over it; a stream to several opens one upload for each recipient's copy, so the default is four such messages to sixteen; 0 is unlimited | 64 |
| `max_inflight` | requests being handled at once | 256 |
| `max_waiting` | listings held open at once for watchers; over it the next is answered at once rather than held, and each held listing keeps an in-flight slot, so keep this well under `max_inflight` | 64 |
| `knock_max_bytes` | the largest knock envelope, on the knock route's own cap, so a stranger's one message is read under a bound of its own; 0 is `max_bytes`, since a knock is a post, and a value over `max_bytes` is refused at startup naming both; in force it is never above 64 MiB, since a knock is a row like any other, and the health answer says the figure in force; the default takes a knock at its longest with four vouches and not five | 20480 |
| `max_knocks_waiting` | knockers one mailbox holds a knock from, counted as rows the relay has whatever the owner has read. One knocker holds one row however often they knock: a second knock from a key replaces the first, so this counts knockers and one identity cannot fill it. A knock from somebody the mailbox holds none from is refused `429` at the cap, with no `Retry-After`, since the relay cannot say when the owner will fetch or remove them, and the sender's knock is not charged for it; 0 is unlimited; at most 1000, for the reason `max_open_uploads` has a ceiling | 10 |
| `knocks_per_hour` | knocks one sender may post in an hour, across every mailbox, beside the post budgets every knock is charged as a post; 0 is unlimited | 10 |
| `max_recipients` | the most recipients one message to several may name. The relay can hold it only where a request has a body to carry the count, opening a stream and a forward from a user: there a request that says it is one copy of a message to more is refused `413`. A plain post's body is the envelope alone and carries no count, so there the relay cannot see the number, and the health answer gives it for a client to hold itself to. A client that leaves the count out is, as far as the relay can tell, sending to one; the setting binds an honest client, and the post budget binds every client. 0 is unlimited, which is the protocol's own ceiling of 32, and a value over 32 is refused at startup; the health answer and `auu-admin status` give the number in force. The default sends to the most in about half of `posts_per_minute` | 16 |

The three queue limits count a stream from the moment it is opened. What
an unfinished upload has reserved is charged against the mailbox's messages
and bytes and against the relay's total exactly as a queued message is. That
holds for an envelope posted beside it and for another stream alike. So a
sender cannot fill a mailbox to its quota under an open reservation and then
complete the stream on top. The reservation is released when the upload
completes or is abandoned. Once expired, it is released by the first of
these to meet it: its sender's next request on it, its sender's open at the
`max_open_uploads` cap, the purge every hundredth request, or a post, an
open, a knock or a courier's delivery that finds the room taken. An attempt
in flight holds the upload's lock, and the purge passes over a locked
upload. So an attempt begun at the last moment holds the room for as long
as it keeps the pace, and one fed nothing until its hunk deadline cuts it,
ten seconds more at most. A reservation lives only as long as it is fed.

The sender's byte budget is charged the same way at the open, with the
whole declared size, so a sender cannot open past it. What comes back when
an upload goes unplaced depends on what the relay held of it. Unplaced
means aborted, expired, purged, an attempt that stopped short and left
nothing, or an attempt that ended with the upload deleted whole. An upload
with kept bytes gives back its size less them. A partial kept for a resume
stays charged while it is kept and gives back the rest when it expires
unplaced. An upload that goes holding no byte gives nothing back. Its
reservation held the recipient's room, and the open's charge is what that
costs. Were it refunded, a sender could hold a mailbox full for nothing,
opening, sending nothing, aborting and opening again at once. So one
identity's reservations cost its `post_bytes_per_hour` however little it
uploads. The rule takes in honest senders too. A first attempt that ends
short of the resume threshold leaves nothing, and neither does a first
attempt the relay's own disk fails, so each is charged the declared size
for the hour. An open the budget then cannot afford is refused `429`
`rate limited: post bytes`, with `Retry-After` saying when the budget
allows it. A placed stream gives nothing back, and neither does an upload
refused at an attempt or at its placement because the allow list or the
channel no longer admits it, whatever it held. An open the relay refuses
before any upload exists, a full mailbox, a full relay or the sender's own
count among the reasons, gives back the whole size. So a refused open
costs a post and no bytes.

When an upload goes holding no byte, the relay logs one `WARN` line,
`upload abandoned unfed`, with the declared size (`size`). Under
`access_log: "full"` it carries the sender's fingerprint (`fp`) and comes
about once a minute for each sender, so an operator can see who is
holding mailboxes full with reservations. Under `minimal` it carries no
fingerprint and comes about once a minute for every sender together. It
is the one fault line that names a sender, and only under `full`, which
names the caller of every request anyway.

`max_open_uploads` bounds the count. A sender at it is refused `429 rate
limited: open uploads` with `Retry-After` set to the seconds until its
soonest upload expires. The sentence says that an upload goes ten
seconds after its open unless an attempt has started, that an attempt is
cut when 64 KiB do not arrive within ten seconds, and that a kept partial
goes sixty seconds after it was kept. The refusal is one the client
waits out. `auu send` sleeps the `Retry-After` and asks again. The
open that asks again meets the sender's expired uploads and lets them go,
so a sender who waited is not refused for a slot the purge had not yet
freed. An upload in flight, its bytes still arriving, holds its slot for
as long as they do, and the relay cannot say when that ends. A sender at
the cap over such uploads is asked back in a second.

`max_upload_opens_per_hour` bounds how many a sender starts. Each open
reserves a recipient's room whatever becomes of it, so the count is
charged at the open, before the reservation, and given back only when the
open reserves nothing. A sender over it is refused `429 rate limited:
upload opens` with `Retry-After`, in a sentence naming the number. A
stream to several opens one upload for each recipient's copy, so the
default of 64 is four messages to sixteen recipients each with an
attachment. A courier never opens an upload, so the setting has no
courier counterpart.

A knock is a post to the knock route, `POST /v1/mailbox/{fp}/knock`, and
the relay judges it in this order: the route's cap, `knock_max_bytes`
plus 64 KiB, before a byte of the body; the post budgets,
`posts_per_minute` and `post_bytes_per_hour`, charged as for any post;
the envelope, which must be addressed to the mailbox and name no channel;
the mailbox, which must exist and not be blocked; the recipient's card,
read and verified then and there, refused `403 the recipient does not
take knocks` for no card, a card that says no and a card that does not
verify alike, since the state of somebody else's card is not a stranger's
to learn, with a card that does not verify said in the log once a minute
naming the mailbox; the sender's `knocks_per_hour`, refused `429 rate
limited: knocks` with `Retry-After`; and the mailbox's
`max_knocks_waiting`, judged inside the store's transaction with the
room, refused `429` with the sentence naming the setting and no
`Retry-After`, the sender's knock token given back. The two 429s are
`limit=knocks` and `limit=knocks_waiting` in the access log. A knock
refused by the store after the post budgets were charged keeps the post
token it spent, as an envelope refused for a full mailbox does. The allow
list is never read on the knock route, and the card is never read on the
post route: a sender the owner admits posts, a stranger the owner's card
invites knocks, and the two doors do not open each other.

Two limits are not settings. An allow list may name at most 1000 senders.
A channel directory may hold at most 64 channels, each with a name of at
most 64 bytes and a description of at most 1024. They are properties of the
protocol rather than of one relay, since the body limit alone would let a
single request queue a quarter of a million inserts. Both sides of a
directory check the same bounds. A directory is `v`, `owner`, `issued` and
`channels`, and each channel `name`, `description` and, when set,
`not_before` and `not_after`. Version 2 adds a rule a channel may carry:
`max_bytes`, the largest message it takes in wire bytes, an envelope's or
a sealed stream's with its manifest, from 1 to 2^62, absent for the
relay's own cap; `no_streams`, true to take no stream; and `no_forwards`,
true to take no courier's delivery. A directory with no rule is version
1, byte for byte as before; one with any is version 2, and a version 1
directory carrying a rule is refused naming the channel and the field.

*Listing 1.4a*
```json
{
  "limits": {
    "posts_per_minute": 30,
    "mailbox_max_messages": 1000,
    "max_inflight": 256
  },
  "access_log": "minimal"
}
```

Per-identity limits are keyed by the fingerprint the relay has already
verified, never by the one a caller claims. So nobody can spend somebody
else's budget by naming them. Per-address limits are keyed by the connection's
own address. The relay terminates TLS itself, so no `X-Forwarded-For` header
is read and sending one changes nothing. A well-formed request with a bad
signature is verified before it is charged, so somebody sharing your address
cannot lock you out of authenticating.

Three replies say the relay is refusing rather than failing:

| status | meaning | what to do |
|---|---|---|
| `429` | out of budget, `Retry-After` says for how long | `auu` waits and retries three times on its own; if it still fails, wait as the error says |
| `503` | too many requests at once | the same, it clears on its own |
| `507` | the recipient's mailbox, or the relay, is full — including a disk that fills part way through an upload | the recipient runs `auu rm` on mail they have read, or the operator makes room; retrying will not help, and the sealed copy waits in `outbox/` for `auu send --resume`, which resumes what the relay kept or opens anew |

**Compatibility.** A relay and the clients that use it go to v0.15.0
once, together, the relay first, and after that versions may differ: a
relay carries any envelope version, ignores a section in a request it does
not know and refuses one marked critical with `needs-newer`, and says what
it can do as `wire_level`. v0.14.0 and before are not supported. The
release note, [`docs/releases/v0.15.0.md`](releases/v0.15.0.md), gives the
order. A v0.15.0 relay and v0.16.0, v0.17.0 or v0.18.0 clients mix in
any order, and so do a v0.16.0, v0.17.0 or v0.18.0 relay and v0.15.0
clients. A v0.17.0 relay is a v0.16.0 relay on the wire, and v0.17.0
and v0.18.0 clients send what v0.16.0 clients send, but for a channel
directory that carries a rule. A v0.18.0 relay is at wire level 2: it
holds a version 2 channel directory, whose channels may carry
`max_bytes`, `no_streams` and `no_forwards`; a v0.17.0 or earlier relay
refuses one at the push, `400` naming the field it does not know. A v0.18.0
relay refuses more than an earlier one, each with a status and a
sentence any of them shows, among them an inline envelope over 64 MiB,
a forward with a path still to go over `max_bytes`, an owner document
issued from the future, a request for a courier's mailbox's channels,
a poster over its carried share (`429`, `limit=carried`), an admin
request of no declared length (`411`), and a body refused before its
signature, which costs a token of the unauthenticated budget and meets
`429` once that is spent. A v0.15.0 relay does not hold
`max_recipients`: it ignores the count on a stream's open and on a
user's forward, and its health answer says no `max-recipients`, so a
v0.16.0 or later client holds a message to several to 32, the
protocol's ceiling, there.
[`docs/releases/v0.16.0.md`](releases/v0.16.0.md),
[`docs/releases/v0.17.0.md`](releases/v0.17.0.md) and
[`docs/releases/v0.18.0.md`](releases/v0.18.0.md) say what else changed,
and the last takes a v0.14.0 relay straight to v0.18.0.

`GET /v1/health` is exempt from all of it, so monitoring does not flap while
the relay is under attack. Its answer says the relay's `max_bytes`,
`knock_max_bytes`, registration mode and `wire_level`: a whole number that
rises when a release gives the relay something a client may depend on. It
is 1 from v0.15.0 and 2 from v0.18.0, which holds a version 2 channel
directory. `auu` refuses a relay's health answer without it. The
most recipients a message to several may name, `max_recipients` as it is in
force, comes in a section of the answer, `max-recipients`, rather than a
field, so that an `auu` from before it reads the answer still.

Every answer the relay sends may carry a `sections` key at its top: the one
place a newer relay may say something an older `auu` does not know. This
release sends one, `max-recipients`, not critical, on the health answer and
on the administrator's status answer. `auu` reads every answer strictly, ignores a section it
does not know, and refuses an answer with a section marked critical,
naming it and saying to update `auu`. A refusal whose words it cannot
read is said with its status and the request. All of a body's sections
together are held to 16 KiB, and a listing page counts them within the
smaller of `max_bytes` and 64 MiB.

Every request body may carry `sections` the same way, and so may what one
relay sends another: a hand-over on `POST /v1/forward` and a report on
`POST /v1/forward/failed`. The relay knows one, `recipient-count`, the
number of recipients a copy of a message to several went to, on opening a
stream and on a user's forward, and holds it to `max_recipients`. On a
hand-over from a neighbour it does not read it, since the first relay held
the sender already. The relay reads every
request body strictly, so a field the request does not have is refused
`400` by name, and it ignores a section it does not know. It refuses a
section marked critical with `400`, code `needs-newer` and the sentence
`this relay (wire level N) does not know section "S", which this request
must not be read without; the relay needs a newer auu`. A refused
hand-over is reported back to the sender in those words and never
retried. The refusal comes where a malformed body's always did: after the
signature on every route that has one, and on registration before it,
since the key is in the body, so it spends no nonce there.

Every refusal's body is `{"error": …, "code": …}`, the code always present,
empty for a refusal of no particular kind, and shaped like a section's
name. `auu` decides on a refusal's code and status and never on its
sentence, which it only shows. A code it does not know is shown as the
relay's sentence and acted on no further, so a later relay may add codes.
A refusal without a code, or with one of another shape, is said by its
status and the request. The codes this release writes:

| code | status | refusal |
|---|---|---|
| `needs-newer` | 400 | a request with a critical section the relay does not know |
| `over-budget` | 429 | a post or stream bigger than a sender's whole `post_bytes_per_hour` |
| `no-directory` | 404 | the mailbox has no channel directory, only `default` |
| `no-knocks` | 403 | the recipient takes no knocks |
| `no-such-channel` | 404 | no channel of that name |
| `channel-closed` | 403 | the channel is outside its period; `at` is when it opens or closed |
| `no-neighbour` | 404 | the forward route names a neighbour this relay does not have |
| `relay-full` | 507 | the relay's storage is full |
| `mailbox-full` | 507 | the recipient's mailbox is full |
| `storage-error` | 500 | the relay could not store or read |
| `newer-allow-list` | 409 | a list issued later is held; `at` is when |
| `newer-card` | 409 | a card issued later is held; `at` is when |
| `cert-required` | 401 | no client certificate was presented |
| `cert-unknown` | 401 | the certificate is not one this relay issued |
| `cert-revoked` | 401 | the certificate has been revoked |
| `cert-expired` | 401 | the certificate has expired |
| `cert-mismatch` | 401 | the certificate names another identity |
| `cert-refused` | 401 | the certificate could not be read as this relay's, with the reason |
| `no-administrators` | 403 | the relay has no administrators |
| `courier-clock` | 503 | a neighbour's courier whose clock is more than a minute and at most five from this relay's (past five its request is a `401`, as anyone's is): `this relay's clock and yours differ by more than a minute; relays keep to the minute`, with `Retry-After: 60` |
| `too-many-recipients` | 413 | a copy of a message to more recipients than `max_recipients`, naming both numbers |

An owner document, the allow list, the card or the channel directory,
is refused `400` with no code when it was issued more than five minutes
ahead of the relay's clock or outside the years 0000 to 9999; a
directory is refused too when it was issued outside about 1677 to 2262,
the range a watch carries as nanoseconds, or when a channel's
`not_before` or `not_after` lies outside the years 0000 to 9999. The
sentence is the reason. It names `issued` and the time, beginning `by
this relay's clock,` when the time is ahead, or it names the channel and
its `not_before` or `not_after`. The check comes right after the
signature verifies, before anything is stored, and `auu` runs it before
it sends one. A held document issued more than five minutes ahead of the
relay's clock, which an earlier release could store, is no bar to a
push: the owner's next push that passes the check replaces it, whatever
its issue time, so such a relay recovers with no operator, and a
running `auu watch` is woken by the replacement as by any change.

`at`, an RFC 3339 time, comes with the three refusals about one. Left
out, it means none. The sentence names the same time for a person reading
the answer by hand. `auu` shows `at` in the reader's zone and never reads
a time out of a sentence.

The HTTP layer has bounds of its own, none of them settings:

| bound | value | what it does |
|---|---|---|
| request line and headers | 32 KiB | over it the answer is `431`, written by Go's `net/http` before the relay sees the request (it reads the block through a 4 KiB buffer, so the cut lands at 36 KiB); the largest header the protocol carries, the request signature, is about 200 bytes, and the relay refuses an auth header longer than its five fields can be before it reads one |
| body of a post | `max_bytes`, never above 64 MiB, + 64 KiB | the envelope with its JSON framing; a forward and a courier's delivery are read the same way |
| body of a knock | `knock_max_bytes` + 64 KiB | the same framing over a knock envelope, which the handler then holds to `knock_max_bytes`, never above 64 MiB, itself, refusing one over it `413` naming the setting |
| body of an allow list or a channel directory | 1 MiB | the envelope the document travels in, base64 and all: sized so that either document at its own cap below fits inside it — a full directory of 64 channels at every cap, every rule set, is 573,918 bytes as the client sends it, and one padded to its own cap below 699,170. Over it the answer is `413` naming the bytes and saying to send the document compact |
| body of every other request | 64 KiB | a registration, a certificate request, an admin token, a stream's open, and a card, whose document has its own cap below; none reaches a tenth of it |
| the signed document inside, per kind | 512 KiB directory, 128 KiB allow list, 512 B card | the bytes the owner signed, which is a different thing from the body that carries them and is checked before the signature rather than after: over it the answer is `400` naming the bytes, the cap and to send it compact. Each is the document at every maximum as a client marshals it compact — 430,350 bytes for a directory, 67,141 for an allow list, 199 for a card, measured — with room above for a signer whose encoder indents |
| the stream `PUT` | the size the open declared | its `Content-Length` must equal what is left of that size, judged before a byte is read |
| timeouts | headers 15 s, body 5 min, response 5 min, idle 2 min | the stream routes move their own deadlines as above |

A body that declares itself over its cap is refused `413` before a byte of
it is read, the sentence naming the cap in bytes. One that arrives without
a length is refused `411` on every authenticated route that reads a body,
the mailbox routes, the two forward routes and the admin routes, and on
the stream PUT; `auu` always declares one. `/v1/register`, which has no
signature to check, still cuts such a body at its cap and refuses it
`413`. On every authenticated route the relay checks what it can before
the body. That is the client certificate, that the auth header parses, the
declared length, and that the identity it names has a mailbox, in that
order, so the length is judged alike for every caller. It reads the body
only then, so a stranger's sixteen megabytes are refused unread. The admin
routes read the body before they look up the administrator, as below. The
signature, which is over the body, is checked after it, the stream PUT
excepted, whose signature is over an empty body and comes before it. Every
refusal before the body closes the connection behind its answer. Those
refusals are that `413`, the `411`, a `401` for a header that will not
parse or an identity no mailbox has, a `503` from the in-flight cap, and a
`429` once the address's budget is spent. Go's `net/http` would otherwise
read up to 256 KiB of the unread body before answering on a connection it
meant to keep, and wait for a body that never came.

A body refused before its signature is checked, for its declared length,
for a read over the cap or for a read that failed, is charged to the
source address's `unauthenticated_per_minute` exactly as a `401` is, and
answered `429` once that is spent. That holds on every route under
`/v1/mailbox/`, on `/v1/forward` and `/v1/forward/failed`, and on the
admin routes. The admin routes read the body before the administrator is
looked up: a body that declares no length is refused `411` with `a request
to an admin route declares its body's length`, one declared over the cap
`413`, and the rest is read whole, at most 64 KiB. So every byte is
bounded and read alike before the administrator is known, and every
refusal before the signature, the `400` for a read that failed among them,
is charged and the same for every fingerprint. The `403` `this relay has
no administrators` is charged as well. `auu-admin` always declares a
length, so nothing of ours meets the `411`.

The relay speaks HTTP/1.1 alone. HTTP/2 is off on the listener and not
offered by ALPN, so a client that offers `h2` is answered over HTTP/1.1.
Every property of the wire above holds under the one protocol the relay's
tests run.

The access log records one line per request. In the default `full` mode that
line names the verified caller and the request path, which together are who is
writing to whose mailbox. Set `access_log: "minimal"` on any relay shared
beyond one team. It logs the route (`POST /v1/mailbox/{fp}`) instead of the
path and omits the caller. That is still enough to operate the relay and to
tell an attack from ordinary traffic. One thing it does not hide, because
it is not in the log at all: a waiting knock's row names its knocker, so
the database says who has knocked at whom until that knock is fetched or
replaced. An operator whose users want no such record turns knocks off by
telling them so. A user does it themselves with a card that says no
knocks.

A file operation under the message directory that fails is answered to the
client as a `500` that says only `storage error`, since nothing the client
can do would help. Such a failure is a directory that has gone, one the
relay's user cannot write, or a disk that will not read. `auu` turns that
into "the relay could not store or read a message (storage error); whoever
runs it needs to look at its log". The log is where the relay says why:

*Listing 1.4b*
```
level=WARN msg="storage fault" path=/var/lib/auu/messages/tmp err="open /var/lib/auu/messages/tmp/3f…: permission denied"
```

One line a minute per path, so a broken disk under a busy relay does not fill
the journal with the same line. A full disk is not a storage fault. It is the
`507` above, and the sender is told whose problem the room is.

### 1.5 Certificates without a public CA

A relay makes its own certificates, from an authority you create on a machine
that has no open sockets. No ACME, no Let's Encrypt, no port 80 or 443.

*Listing 1.5a*
```
auu-ca init  --name "Your Organisation"                       # asks for a passphrase
auu-ca relay --host relay.example.com --out relay-bundle.json  # asks for it again
scp relay-bundle.json relay.example.com:
ssh -t relay.example.com 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json \
  /etc/auu/relay-bundle.cred && rm relay-bundle.json'
rm relay-bundle.json
auu-ca show                                                   # asks for nothing
auu-ca kit   --host relay.example.com --relay-binary bin/linux_amd64/auu-relay \
  --admin @admins --out relay.example.com.zip                 # the bundle, packed with the relay
```

Every private key in that directory is encrypted under a passphrase you
choose at `init`. So a backup, a snapshot or a stolen disk yields
certificates and nothing else. `init` and `relay` ask for it. `show` never
does, because it reads no key. For a script, `--passphrase-file PATH` reads
the first line of a file. With standard input not a terminal the first
line of standard input is used, so a secret manager can pipe it in.
`auu-ca passphrase` changes it.

The passphrase is not recoverable and is stored nowhere. Losing it is losing
the authority, which means every machine enrolling again under a new anchor.
So keep it where you keep the backup, and not in the backup.

`init` creates a **trust anchor** and two authorities beneath it, one for
server certificates and one for client certificates. `relay` issues one relay
a **signing intermediate** from each as a bundle. `kit` issues the same
bundle and packs it with the relay binary, the settings and administrators
for the host, the unit and an installer. So the deployment guide's steps
are one script on the host. The archive is handled exactly as the bundle
file is. `show` prints the anchor's hash, which is what an enrolment token
carries, and when each relay's intermediates expire. It warns about a
bundle or a kit still on this machine.

The bundle is the relay's two signing keys in the clear. That is why the
file is deleted at both ends the moment `systemd-creds encrypt` has sealed
it to that host. It is also why `auu-ca show` warns for as long as the local
copy is still there. The relay's unit unseals the credential at start with
`LoadCredentialEncrypted=` and the relay reads it as
`tls.bundle_credential`. A relay not under systemd takes the file itself as
`tls.bundle`. It is one command per prompt, for the authority's passphrase,
your ssh password and your sudo password. That is because two programs
asking on one terminal at once get each other's keystrokes, which is what
`auu-ca relay --out - | ssh …` does. `--out -` puts the bundle on standard
output and everything else on standard error, for keeping it off every
disk. The deployment guide has that form. `auu-ca` does not shred. On a
filesystem with snapshots, or any SSD, overwriting proves nothing. The
remedy is to delete the file promptly, or not to write it.

Everything above the line stays on that machine:

*Listing 1.5b*
```
  KEPT OFFLINE — every key here
  ─────────────────────────────────────────────────────────────────
                        TRUST ANCHOR
                  ┌──────────┴──────────┐
             SERVER CA              CLIENT CA
  ═══════════════╪═════════════════════╪═══════════════════════
  ON THE RELAY   ▼                     ▼
     SERVER SIGNING INT         CLIENT SIGNING INT
     names: this relay's only   issues at enrolment
            │ mints a 30-day leaf       │
            ▼                           ▼
       the relay's own cert       client certificates
```

The bundle holds two signing keys and no more: this relay's own and its
client authority's. A relay peered with another also holds the courier's
identity, which is 1.10's and is not in the bundle. What a copy of its disk
buys an attacker is the ability to be that one relay and to issue client
certificates. Those certificates are useless without the identity keys they
pair with. It never buys the ability to extend trust, to issue for another
name, or to make an authority. The server intermediate carries **name
constraints** for this relay's hosts. It excludes outright whichever kind of
name, DNS or IP, it was given none of, because a constraint restricts only
its own kind. Each intermediate is restricted to its own purpose and
forbidden from issuing a further authority. Go's verifier enforces all of
it, so they are boundaries rather than intentions.

Both intermediates are **disposable**, and that is the point of the extra
level. If the relay is compromised:

*Listing 1.5c*
```
auu-ca relay --host relay.example.com --out relay-bundle.json
scp relay-bundle.json relay.example.com:
ssh -t relay.example.com 'sudo systemd-creds encrypt --name=relay-bundle relay-bundle.json \
  /etc/auu/relay-bundle.cred && rm relay-bundle.json && sudo systemctl restart auu-relay'
rm relay-bundle.json
```

Machines trust the anchor, not the intermediate, so nobody re-enrols. The
relay keeps the retired client intermediate's certificate until it expires,
so the certificates it issued go on verifying. The retired signing key
mints nothing the relay will honour. A certificate with a serial it never
recorded is refused, and one with a recorded serial must carry the key that
row records.

The same two commands are the **yearly renewal**. The intermediates last a
year, and `auu-ca show` says when. For the last sixty days the relay warns
in its log once a day.

**Back up the `auu-ca` directory.** It is the only thing that cannot be
replaced. Losing it means every machine enrolling again under a new anchor.
The keys in it are encrypted, so the backup is worth nothing to whoever finds
it without the passphrase. Without the passphrase it is worth nothing to you
either, so keep the passphrase somewhere the backup is not. With the pipe
above, that directory is the only secret the offline machine holds. No
bundle ever had a path on it. If you wrote one with `--out FILE`, it is in
your backups until you delete it, and `auu-ca show` says so.

#### 1.5.1 How a machine comes to trust it

The enrolment token carries the anchor's hash. `auu enrol` fetches the anchor
from the relay over a connection nothing has verified, checks it against the
token, and pins it. From then on it trusts that anchor and *nothing else*
for this relay, not the system roots either. The assumption is one you were
already making. Whoever handed you the token could have handed you the wrong
relay URL. Putting the hash in the token makes it checkable.

Joining without a token, or setting the relay up yourself, with `HASH` as
`auu-ca init` printed it:

*Listing 1.5.1a*
```
auu init --name you --relay https://relay.example.com:9443 --anchor HASH
```

An identity that already exists pins without being replaced. That is what
the first administrator needs, since their export line is already on the
relay:

*Listing 1.5.1b*
```
auu anchor pin HASH
auu anchor            # what is pinned, and the relay's current signing intermediate
```

Nothing is written until the anchor the relay serves matches the hash. A wrong
hash, or a relay that cannot serve one, leaves the identity as it was. A relay
serves its anchor whenever it runs from a bundle, whether or not it requires
client certificates.

#### 1.5.2 If the relay's authority is rotated

A machine records the server signing intermediate it last accepted. A *newer*
one is a rotation, since only the offline authority can issue one. So it is
accepted, recorded, and reported once. An *older* one is a retired authority
being replayed, and is refused. `auu` names both issue times to the second.
It says that either the operator restored an earlier bundle or somebody is
replaying a retired one. It says to ask the operator, since only they can
tell which. Enrolling again with a new token is what accepts what the relay
serves now. There is one case this cannot help with, and it is stated rather
than hidden. A stolen intermediate that has not yet been rotated away is
indistinguishable from the real relay, and detecting that is outside the
protocol.

#### 1.5.3 What still needs a public certificate

Nothing, unless you want ordinary tools to reach the relay. `curl` linked
against LibreSSL, which is what macOS ships, cannot speak ML-DSA at all.
Neither can OpenSSL before 3.5. `auu` can, because it is Go 1.27. If you want
`curl https://relay.example.com:9443/v1/health` to work for a monitoring system,
use *Your own certificate* below with a publicly trusted one. Tokens will
then carry no anchor.

### 1.6 Your own certificate

*Listing 1.6a*
```
auu-relay --tls-cert /etc/ssl/relay.pem --tls-key /etc/ssl/relay.key
```

### 1.7 Running under systemd

The relay needs no capability. It makes its own certificate, so no
particular port is required. The example settings use 9443. A minimal
unit:

*Listing 1.7a*
```ini
[Unit]
Description=auu relay
After=network-online.target

[Service]
User=auu
Group=auu
ExecStart=/usr/local/bin/auu-relay --config /etc/auu/relay.json
LoadCredentialEncrypted=relay-bundle:/etc/auu/relay-bundle.cred
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/auu
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

If you do put the relay on 443, add `AmbientCapabilities=CAP_NET_BIND_SERVICE`
and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` to the unit. Nothing else
changes, and port 80 has no use here. `ReadWritePaths` must cover the
database and the message directory. The bundle arrives as a credential.
`LoadCredentialEncrypted=` unseals `/etc/auu/relay-bundle.cred` at start
into a directory only this service can see. The settings name it as
`"bundle_credential": "relay-bundle"`. That is the name before the colon,
the one `systemd-creds encrypt --name=` was given. The administrator file
only has to be readable, so leaving it at `/etc/auu/admins` under
`ProtectSystem=strict` is right. The relay never writes it.

**Run NTP on the host.** A relay holds every user's request to within five
minutes of its own clock, and a relay that forwards is held closer by its
neighbours: relays keep to the minute. A courier's request whose clock is
more than a minute from the neighbour's, and no more than five, is refused
`503` with `Retry-After: 60` and the code `courier-clock`, and the
neighbour's log says so once a minute for each of its neighbours. Past five
minutes the request is refused `401` before its signature is read, as any
request that far out is, and the courier takes that for a refusal of its
enrolment (section 1.10):

```
level=WARN msg="a neighbour's courier was refused: its clock and this relay's differ by more than a minute; relays keep to the minute, so check NTP on both" neighbour=foo
```

The relay whose courier was refused says it from its side, once a
minute for each neighbour, and its mail waits until the clocks agree:

```
level=WARN msg="courier: a neighbour says this relay's clock and its own differ by more than a minute; relays keep to the minute, so check NTP" neighbour=bar
```

A relay that forwards nothing is held to nothing closer than a user's
five minutes, but its clock is still every user's on it, so run NTP
there too. Section 1.10 says what the queue does while it waits.

A complete walk-through for a Linux host with systemd is in
[`docs/deploy-linux.md`](deploy-linux.md), with the unit and the
settings file beside it under `docs/systemd/`. It covers the user, the
directories, a hardened unit and the first administrator. The other side,
for the person who has only been sent a token, is
[Enrolling on a relay with certificates enabled](enrolling.md). It runs
from installing Go to adding a second machine.

### 1.8 Client certificates

A relay can require each machine to hold a certificate of its own, issued when
that machine enrols:

*Listing 1.8a*
```json
"client_certs": { "mode": "required" }
```

Not beside `"registration": "open"`. Registration is how a machine gets a
certificate and consults none. So with registration open a machine whose
certificate was revoked would re-register with no token and be issued a
new one, and revocation would revoke nothing. The relay refuses to start
on that pair, in one sentence, and so does `auu-ca kit`. `token` or
`closed` is what certificates go with.

What it adds is a **second, per-machine credential**. Every request the relay
verifies is already signed by the identity key, so the relay always knew who
was asking. The health check and a key lookup are not signed, since the relay
reads no signature on them. What it could not tell was one of your machines
from a copy of your `~/.auu` on somebody else's. A certificate is generated
on the machine, its private key never leaves, and the relay records the
serial. So a laptop can be revoked without touching the identity. A machine
presenting a certificate the authority did not issue fails the TLS
handshake. One presenting none completes it and is refused at every mailbox
route and at the key lookup. Without a certificate a machine reaches the
trust anchor, the health check and enrolment, which a new machine needs
before it has one. It also reaches the administration routes if it signs as
an administrator. An administrator's authority is the file on the relay's
host, so administering a relay never depends on holding a certificate from
it.

What it does not add is confidentiality. Message contents are sealed end to end
with HPKE either way, and the relay can no more read them with client
certificates on than off.

The keys are **ML-DSA**, the post-quantum signature from FIPS 204, via Go's
`crypto/mldsa`. They are at the parameter set the authority was created
with, `auu-ca init --mldsa`, 44, 65 or 87. The default, 65, is the level-3
partner of the ML-KEM-768 inside the X-Wing KEM the messages use. So the
transport authentication is post-quantum at the same level. The set is the
anchor's, and every machine's key must match it, stronger or weaker. A
machine asks the relay which before it generates one, and the relay refuses
any other. Changing it means a new anchor and every machine enrolling again.

ML-DSA requires TLS 1.3, which the relay insists on everywhere, with
`X25519MLKEM768` as the only key exchange and no setting to relax either.
TLS 1.3 is also the first version to encrypt the client's certificate rather
than send it in the clear, and the certificate names a fingerprint. That pin
is the relay's own TLS. A relay run with `tls.mode: "off"` behind a
terminator gets the terminator's, which is the operator's to hold to the
same.

The certificates are issued by the client signing intermediate in the relay's
bundle, the one `auu-ca relay` wrote. The relay holds no other key for it and
nothing more needs creating or backing up. A lost or stolen intermediate is
replaced by running `auu-ca relay` again. Every machine already enrolled
keeps working, as *Certificates without a public CA* above describes. Only the
`auu-ca` directory needs backing up.

Certificates last a year by default. `auu` renews them from sixty days out,
over the certificate it already holds, so a machine in regular use never
reaches the day it stops working. A home under a passphrase renews in
receive scope, the plain `auu unlock`. What all of this looks like from the
user's chair is [Enrolling on a relay with certificates enabled](enrolling.md).

To take one away:

*Listing 1.8b*
```
auu-admin certs ls                        # every machine, and whose it is
auu-admin certs revoke SERIAL --reason "laptop stolen"
```

Revocation takes effect on that machine's very next request. Every request
already resolves the caller's mailbox, so resolving the certificate's serial
beside it costs one indexed read. There is no revocation list to distribute
and nothing to wait for.

The relay must be able to see a certificate, which means terminating TLS
itself. A relay with client certificates required and TLS off refuses to
start rather than refuse every request afterwards.

### 1.9 Keeping a relay private

**What `registration: "open"` costs, in one place.** Open registration means a
registered identity is anybody who asked, and several things this relay serves
to its registered identities are therefore public: the cards of users who chose
to be listed, the answers to key lookups, and — if you peer — the list of
neighbours you accept forwarded mail from, each with its courier's fingerprint.
That last one is new in this release and is the reason this paragraph is here
rather than only beside the route in 1.10.

Two things bound it. A fingerprint is a global identifier where a relay name is
deliberately local, so what a reader learns is *which* relays carry mail to you
and not merely what you call them. But an open relay cannot forward outward at
all — `courier.home` beside open registration refuses to start — so what is
disclosed is who carries in, never who you carry to. And the list cannot be
withheld from your own users without making forwarding unusable for them: a
recipient who cannot read it cannot admit a courier, and cannot be reached from
any other relay. An administrator-only list would make you a help desk for every
fingerprint.

So the remedy is not a setting on the route. It is `token`, which is the remedy
for the rest of what open registration discloses too.

Set `registration` to `token` and nobody creates a mailbox without an
invitation an administrator signed. Combined with each user running
`auu allow push`, that keeps a relay to a known group. `closed` stops new
mailboxes altogether while leaving the existing ones working.

In every mode the display name a registration carries is held to the
export line's rule and refused `400` otherwise. The rule is letters,
digits, `.`, `_` and `-`, at most 64 bytes. That is because the relay
serves it to every enrolled machine and the administrator's terminal.
`auu lookup` and `auu-admin` print a name from a relay older than that
rule with anything unprintable escaped, the confirmation before a mailbox
is removed included. Every client prints a relay's refusal the same way,
so a relay's own sentences cannot drive a terminal either. A machine's
certificate label is stripped of the same characters a channel name may
not hold before it is stored.

The relay stores nothing it can read and needs no backups beyond whatever is
still in transit. The relay's bundle can be reissued from the offline
`auu-ca` directory, which is the thing that does need backing up.

None of that is a substitute for keeping the host itself secure. The relay
defends the people using it from the relay. It cannot defend itself from
whoever has root on the machine it runs on. Whoever has root can stop it,
delete or delay mail, read the access log, take the signing keys in its
bundle, or replace the binary with one that does something else. Treat the
host as you would any server that carries other people's mail. The operator
alone has an account on it, nothing else runs there, it is patched, and the
unit's hardening from the kit stays in place. What an attacker on the host still
cannot do is read a message or write one as somebody else, because the keys
for that were never on the machine.

### 1.10 Forwarding to another relay

A relay can carry mail to a relay it neighbours, so that somebody on yours
can write to somebody on theirs without either of them joining the other's.
Nothing in this section is on by default: a relay with no `courier` block
forwards nothing and accepts nothing forwarded, which is what every relay
did before this existed.

The arrangement is the one two administrators can set up between themselves
in an afternoon, and it rests on nothing more than their trusting each other
to deliver mail. It cannot rest on less, and it needs no more: a message is
sealed for its recipient, so a relay carrying one cannot read it, forge it
or re-address it. What relay trust covers is delivery, and that is all.

**A relay forwards by being a user of its neighbour.** It has an identity of
its own — a *courier* — enrolled on the neighbour with a token the
neighbour's administrator issued, exactly as a person enrols. So each relay
knows a neighbour twice, and each half is a thing that already exists:

- **To dial one**, an entry in the *courier home*: an ordinary `auu` home
  the relay's user owns, named by `courier.home`. The name you give a relay
  there is the name senders write in an address.
- **To accept from one**, a line in the *couriers file*, named by
  `courier.authorized_file`: export lines in the format the administrators
  file uses, one per neighbour, each line's name being your name for that
  neighbour.

Set the home up as the user the relay runs as, with no passphrase, since a
relay cannot be asked for one and runs no agent:

```
sudo -u auu env AUU_HOME=/var/lib/auu/courier auu init --name relay-a
sudo -u auu env AUU_HOME=/var/lib/auu/courier auu enrol --name bar TOKEN
sudo -u auu env AUU_HOME=/var/lib/auu/courier auu id export
```

The user and the directory are the shipped unit's — `User=auu` and
`StateDirectory=auu` — so the home is under the one path the unit can write
and nothing in it changes for this.

The last line prints the export line to send to the neighbour's operator,
who puts it in their couriers file under their name for you. They send you
theirs, and you do the same. The file is theirs to protect as the
administrators file is: the relay refuses to start if it is writable by
group or others, since whoever can write it decides which relays may put
mail into this one's mailboxes.

**Use one name for a neighbour in both places.** Nothing can enforce it. A
relay cannot learn a neighbour's identity from its health answer. So the
relay says at every start which names appear in one and not the other:

```
level=INFO msg="courier: this relay accepts mail from a neighbour it cannot dial; a reply along that name will be refused at its first hop" name=qux
level=INFO msg="courier: this relay dials a neighbour it accepts no mail from; that neighbour's replies and its undeliverables will be refused here" name=baz
```

Neither is a refusal, because one-way peering is a thing you may want: a
relay may accept from a neighbour it never dials, or dial one that accepts
nothing from it. But a name in only one place is also what a typo looks
like, and what it costs is somebody's reply, so the start says it and you
decide which it is. A relay given a home and no file, or a file and no
home, is one-way on purpose and is not remarked on.

**The numbers need a peering.** Every other setting under `courier` bounds
forwarding, and only `courier.home` or `courier.authorized_file` makes the
relay forward at all. So a courier setting, in the file or as a
`--courier-*` flag, with neither of the two set once the flags are merged
in, stops the relay at its start:

```
courier sets bounds on a peering this relay does not have: the numbers
under courier bound forwarding, and courier.home or
courier.authorized_file is what makes this relay forward at all; give it
a peering, or delete the courier block and the --courier flags
```

A home or a file given as `""` or `null` is no peering. A flag alone,
`--courier-max-hops 4` with no path, is refused as the same line in the
file is. A `--courier-home` or `--courier-file` flag may supply the path
the file left empty, and the relay takes it. `--print-config` prints the
`courier` block only for a relay that peers, so its output still loads.

The relay also says at the start when its own certificate for a neighbour
cannot be read, naming the home and what to run in it, rather than leaving
it to be found by the first person whose mail it was meant to carry.

**What the courier key is, and what a copy of it buys.** The courier's
identity is the second signing key a relay holds, after its certificate
authority's, and a deliberate exception to the rule that a relay holds
none. What a stolen copy buys is the ability to post at your neighbours as
your relay, which their own budgets bound and which their operator ends by
removing one line from their couriers file. It buys no message, and nobody's
identity: the courier is a postman, not a reader.

That line ends less than it may sound, and the difference matters to whoever
removes it. It ends the key's standing *as a courier* there: the return paths it
could write under your relay's name, and the courier budgets it drew on. It does
not end its mailbox. A courier is an ordinary enrolled user of the relay it
forwards to, and the forward route is open to every registered identity. A
non-courier is refused only for writing a return path it has no right to. So the
key stays an identity able to post, and to forward its own mail as any user
does, under a user's budgets rather than a courier's. What ends that is what
ends it for any user: the neighbour's administrator blocks the identity,

```
auu-admin blocks add FINGERPRINT --reason "stolen courier key"
```

which refuses it at every authenticated route. A neighbour told of a stolen key
should do both: remove the line so the key can no longer speak for your relay,
and block it so it can no longer speak at all. Protect the file as the
relay's bundle is protected — the relay's user alone, 0600, under the unit's
hardening.

**A relay that dials cannot leave registration open**, and it refuses to
start if you try:

```
registration is open and courier.home is set: the forward route is open to
every identity with a mailbox here, so with open registration anyone can
make one and post through this relay to its neighbours, under this relay's
own courier. Set registration to token or closed, or remove courier.home
```

The forward route is open to every identity with a mailbox on this relay.
It has to be, since forwarding is something your own users do. So with
`registration: open` a stranger makes a mailbox in one request and posts
through it. It reaches your neighbour under *your* relay's courier
identity, spends the budget they gave you, and fills the queue you are
holding for them. Nothing of it is delivered, because the recipient's
allow list runs at the relay that delivers. But the remedy your neighbour
has is to stop accepting from you. It is a refusal rather than a warning
because the two settings are each reasonable alone and together undo what
one of them is for.

Accepting forwarded mail under open registration is not the same thing and
is allowed: what arrives that way is bounded by your couriers file, and
nothing leaves on a stranger's account.

**What the relay holds, and for how long.** Mail this relay has taken for a
neighbour waits in a queue: one row and one file per envelope, under
`courier.queue_max_bytes` and `courier.queue_max_messages` across the
relay, and `courier.queue_max_messages_per_poster` and
`courier.queue_max_bytes_per_poster` for each person posting. The
relay-wide pair is two bounds because bytes do not bound files: the
smallest envelope is about a hundred bytes, so a gigabyte of them is ten
million rows and ten million files, and a relay that fills up should say
so while it still has somewhere to write the saying. Over any of them the
relay answers `507` and the sender tries again later. The queue empties
itself as the neighbour takes what is waiting, so there is nobody to tell.

A neighbour is held to the relay-wide pair, to
`courier.queue_max_messages_per_courier` in place of the per-poster count,
and to no per-poster byte bound at all: a courier carries many people's
mail, so one person's share of the bytes would refuse a busy neighbour's
whole queue. Its own share of the rows is ten thousand by default, a
hundred times a person's. It is there because the relay-wide pair bounds
every poster together and not any one of them. One peer whose mail is not
moving on, because what it sends through you is bound for somewhere that is
down, would reach the relay-wide count by itself and everybody else's mail
would be refused on its account. Like every per-poster bound here it counts
that poster's waiting rows whatever they are addressed to, so it is a share
of your queue and not a share per destination: a neighbour with its whole
share stuck for one unreachable relay is refused for a reachable one too,
and the remedy is theirs, to stop sending what they cannot get delivered.

Its own posting is bounded by
`courier.posts_per_minute` and `courier.post_bytes_per_hour` rather than by
a user's rates, for the same reason, and the bytes there are unlimited by
default. So what stands between one neighbour and the whole of your queue
is `courier.queue_max_messages_per_courier`, with the relay-wide pair
behind it, and, for a neighbour that floods you anyway, one line removed
from your couriers file.

**How the queue empties.** One worker per neighbour, woken when mail for it
arrives and by its own timer, takes the oldest first and posts each to that
neighbour's forward route. A neighbour that is not answering is left alone
for a minute, then two, doubling to an hour, less a random part so that two
relays which lost the same cable do not knock on the same second every hour
for a week. The backing off is per neighbour and not per message, since a
neighbour that is down is down for every message waiting for it. A
neighbour that refuses one message finally — an address it cannot route, a
request it will not take — ends that message and goes on to the next, and
the sentence it gave is kept with the hop's name in front of it, so the
person who sent it reads which relay refused and why.

A neighbour that will not accept this relay's courier at all, a `401` for a
line removed from its couriers file or a certificate it refuses, holds every
row for it an hour at a time, since no retry mends it and the operator is
told. A clock is different. A neighbour holds a courier's request on the
forward route and the report route to within a minute of its own clock,
judged only once the request's signature has verified, so a stranger naming
a courier's fingerprint learns nothing from the answer. Between one and five
minutes out, it refuses `503` `courier-clock` with `Retry-After: 60`, and
this relay waits the minute and asks again, as it does for any busy answer,
and says once a minute that the two clocks differ (section 1.7 has both log
lines). The mail moves again the minute NTP brings either clock back. Past
five minutes the neighbour's answer is the `401` any request that far out
gets, before the signature is read, so the row waits the hour as for a
refused courier.

`courier.forward_ttl` is how long the relay keeps trying a neighbour that
is not answering — three days by default — after which the mail is failed
and the person who sent it is told. `courier.max_hops` is how many relays
one address may name, counting the path still ahead and the hops already
taken together. It is at most 32, which every client holds an address to
as well, so an address that this relay would refuse is one a sender is
told about before anything is sealed.

**What is left after a message is gone.** The moment a neighbour takes an
envelope the file and the recipient's fingerprint go, and what is left is
one row naming who posted it, your name for the neighbour, and the address
it came by and was going on to. That row stays for as long as something
could still come back about the message — `courier.forward_ttl` for each
hop it had left to go, so three days at the defaults for the last hop and
longer for a message with further to travel — and is then purged. A
message that failed keeps the hop's sentence for a day, so its sender can
read what happened, and then goes the same way. A message still waiting is
never purged: its own `courier.forward_ttl` ends it, and that tells the
sender rather than leaving them to find their mail gone.

**When a message cannot be delivered.** The relay that finally cannot deliver
tells the one behind it, which ends its own row and tells the one behind that,
until the news reaches the row whose poster is the person who sent the message.
Both ways a message can fail travel that way: a hop refusing it, and a hop
giving up on a neighbour that never answered once its own `courier.forward_ttl`
has run out. The second matters as much as the first, because a relay whose
neighbour is down has already taken the message and answered for it, so the
relay behind it is holding a row it thinks arrived and would otherwise never
hear anything about it at all. They read it with `auu queue`: the row is `final`, with a code —
`refused` or `gave-up` — and the sentence the relay that failed gave, with
each hop's name in front of it as the news came back, so `bar: baz: no such
mailbox` is baz refusing, reported through bar, both named as *your* relay and
its neighbour name them.

A relay can only report on a message it was actually handed, and once, so a
neighbour cannot end mail it was not carrying. `courier.reports_per_minute`
bounds how fast one may report at all, beside its posting rate, because an
undeliverable is not mail arriving.

A report can arrive before the relay behind knows the id it names, and is
not lost for it. The relay behind writes down the id it was answered with
only after reading the answer, and one that crashed after the neighbour's
`201` learns the id only when its own retry is answered `already carried`;
so a report that comes back fast enough meets `404`, no such message was
handed to you. That answer is not final: the report row alone waits on the
ordinary backoff, the rows behind it going on, and is asked again until its
own end, the `courier.forward_ttl` it was queued with — three days by
default — which is written in the row and so outlives a restart. Your log
says so once in a while (`a neighbour does not yet know the message a
report names; it will be asked again`); at that end the row is ended as
any row still waiting is, in the `gave up on mail for a neighbour` line,
or, when a `404` happens to come back just as the end passes, in the line
below. Each try is charged to your relay's
report budget at the neighbour, so a stale id costs the one asking and the
neighbour keeps nothing for it. A `409`, already reported, is final as it
always was. A row waiting so is still a row in the neighbour's share of
your queue: a neighbour that answers every report `404`, as one whose
couriers file and home name you differently does, keeps each for its whole
`courier.forward_ttl`, and enough of them leave no room for its own mail,
which is a reason to fix that naming when the start names it.

Two rows handed to one neighbour can carry the same id, when the neighbour
deleted its database and began its numbering again. A report is matched to
the newest of them, whatever state it is in, since a report comes from the
neighbour's present numbering; if that row has already been told how it
ended the report is answered `409`, and never taken for an older row still
handed. So the same report sent again after its answer was lost cannot end
the older generation's message with the newer one's sentence.

It is a tenth of the posting rate rather than equal to it, and the reason is
worth stating because the two numbers sit side by side in the table above and
invite the opposite guess. A report costs this relay a row of the reporting
neighbour's own share of the queue — `courier.queue_max_messages_per_courier` —
so the question the rate answers is how fast one neighbour may spend that share
on reports. At sixty a minute it needs nearly three hours to fill it. At the
posting rate of six hundred it would need about seventeen minutes. Nothing is
lost by the slower drain: a relay passing back a long backlog of undeliverables
honours the `Retry-After` it is given, and `courier.forward_ttl` is three days
by default, so the news travels over hours rather than minutes and nobody's mail
is affected by the wait. A report the next hop back will not
take — it still holds no such row when the report's own
`courier.forward_ttl` has run, or it has already been told, or the peering
only goes one way, or its queue is full — is a line in your log naming that neighbour, and that line is the
only trace there will be. A report is never made for a report, so a chain ends
rather than echoing.

Nothing tells the hop behind later, and it is worth being plain about why,
since it is the one place news is lost rather than delayed. The row that would
have to notice is one that relay has already handed over, and a handed row that
hears nothing is the ordinary shape of success: a message delivered produces no
report at all. So a relay cannot tell a delivery from news that never arrived,
and ending handed rows on a timer would tell every sender that every delivered
message had failed. `courier.forward_ttl` ends a row that is still *waiting*,
which is a relay that never got the message away, and that is a different
thing. What it costs when it happens is that the sender reads `handed over`
until the row is purged and then reads nothing. What keeps it rare is that it
takes a peering an operator has half-configured, or a queue already at its
bound, on top of a message that could not be delivered in the first place.

The relay also remembers the envelopes it has carried, by a hash of the
recipient and the ciphertext, so that it never carries or delivers one
twice: a retry whose answer was lost is idempotent, and mail going round in
a circle stops at the first relay it comes back to. A hash is kept for as
long as the envelope could still be alive in the network ahead of it, and
`courier.carried_max_rows` bounds how many stand at once. A hash whose
window has passed stands for nothing and is not counted, though it waits for
the purge to go. At that ceiling the relay also lets go any hash whose
window ended while the request ran, as it lets expired uploads go before
refusing for room, says so in its log (`expired carried hashes removed`),
and asks again; it refuses to take anything new only when the ceiling is
still reached, rather than forgetting a hash that stands, since forgetting
is what the table exists to prevent. The refusal names the setting.

A hash outlives the row that wrote it, so a share of the queue does not
bound it. A row handed on leaves the queue at once, and its hash stays.
So each poster has a share of the hashes as well:
`courier.carried_rows_per_poster` for a person, by the fingerprint their
signature proved, and `courier.carried_rows_per_courier` for a
neighbour, by its courier's. A share is the most hashes a poster may
have standing at once. A forward's hash is kept one
`courier.forward_ttl` for each relay the envelope's path still names,
and costs one for each. So an envelope whose path still names three
relays costs three, and none costs more than `courier.max_hops`. A
delivery into a mailbox here, whose path names none, is kept one
`courier.forward_ttl` and costs one. The charge is the last thing before
the write. A refusal takes nothing from the share, and neither does a
retry of an envelope this relay already carries.

What a poster may spend is the share divided by 1 + H, where H is
1 + 1/2 + … + 1/`courier.max_hops`. 1 + H is 3.72 at the default eight
hops. The poster may spend that much at once, and that much again each
`courier.forward_ttl`. Sized so, a poster's standing hashes never pass
its share, whatever its mix of paths. The price is the sustained rate:
about 27% of the share each `courier.forward_ttl` at the default eight
hops. At the default shares that is 16,810 every 72 hours for a person
and 67,243 for a neighbour: as many hashes on a path of one relay, an
eighth as many on a path of eight.

Over the share the relay answers `429` with a `Retry-After`, and the
sentence names the setting. The access log says `limit=carried`. Left
unset, the shares are a sixteenth and a quarter of
`courier.carried_max_rows` as you set it: 62,500 and 250,000 at the
default. Since standing hashes never pass the share, nobody fills the
ceiling alone: sixteen people's shares, or four neighbours', add up to
it. An unlimited ceiling takes the default ceiling's fractions.
`--print-config` prints the numbers on a relay that peers.

The floor of a share is `courier.max_hops` × (1 + H), rounded up: 30 at
the default eight hops. Below it, what a poster may spend at once cannot
pay for a hash on the longest path. A share worked out from the ceiling
is raised to that floor and stops at a nonzero ceiling. A share you set
must be at least the floor. It must be no more than a nonzero ceiling,
since the ceiling would always be met first. Where the ceiling is itself
below the floor, a share you set must equal the ceiling or be 0. Such a
relay forwards no path naming more relays than its share over 1 + H:
with a ceiling of 20, five. With shares of 0 it forwards any path. The
ceiling stays the last word: a poster within their share is still
refused `507` when the relay holds `courier.carried_max_rows` hashes.

A neighbour offered an envelope this relay already holds answers `409`, and
what the relay behind makes of it depends on what comes with it, because a
repeat has more than one cause and they end differently:

- **The id of the relay's own row for it**, when the repeat is a retry whose
  first answer was lost. The row is handed, as the lost answer would have made
  it.
- **The id, a code and a sentence**, when that row has since ended there. Its
  report came back to a relay that never heard the id it names, and could not
  take it. This answer is how the news arrives instead. The row ends the same
  way and the report goes on back, so the sender reads the far relay's reason.
- **The id of the message it became**, when the neighbour was the last hop and
  delivered it. Handed. The id is kept with the hash rather than looked up in
  the mailbox, so it survives the recipient reading and removing the message.
- **Nothing**, when none of those is so: the envelope was never this caller's
  there, which is mail that has gone round in a circle and come back to where
  it started. The row ends as refused, and the sender reads
  `refused: …: already carried` with each hop named in front.

A courier is a registered identity of the relay it posts to, so it has a
mailbox there as any user does. Nothing writes to it and nothing reads it:
mail for the people a relay serves goes to their own mailboxes, and a
courier's is a side effect of enrolling. Left ordinary it is a mailbox any
registered identity can fill at your expense, so a listed courier's mailbox
refuses every sender, as a mailbox with an allow list naming nobody would,
and nothing distinguishes it from one on the wire. A post, a post to a
channel, a stream, a forward delivered into it and a fetch of its channel
directory get the sentence a refused sender always gets, the fetch with
the `403` a restricted mailbox answers rather than the `404` of a mailbox
with no directory:

```
sender is not on the recipient's allow list
```

and a knock gets the sentence a mailbox that takes no knocks always gets:

```
the recipient does not take knocks
```

which is also what a mailbox with no card, a card that says no and a card
that does not verify each get. There is no list to write: an allow list
naming nobody cannot be signed, since an empty one admits every registered
sender and one naming only the owner is refused, so the relay holds that
list for a courier's mailbox itself and answers as it would. A watch that
names a courier's mailbox among its peers drops it without a word, as it
drops any peer that has not admitted the watcher.

Saying more would cost you something on one route, a forward's delivery.
A sender on another relay, with no mailbox here, reads its answer through
the forward's report, so a refusal of its own there would let anyone
holding a courier's fingerprint ask which relays you accept forwards from,
one fingerprint at a time. The other routes tell their callers nothing
new: each answers only your registered identities, and `GET /v1/couriers`,
below, lists every courier to all of them. They answer as the forward
does so that a courier's mailbox looks like a refusing one wherever it is
asked about, and no route only your users reach sets it apart beside the
forward's silence.

This is a refusal the relay can make because the mailbox that needs it is
always at the relay whose file names its owner: a courier enrols at its
neighbour so that its relay can forward through it, and those forwards are
accepted only where that neighbour's file lists it. A relay that has not
admitted an identity treats that identity's mailbox as any other, which is
right: it has no grounds to call it anything else.

**Your users can read your couriers file, and they have to.** `GET
/v1/couriers` answers every registered identity of this relay with the
neighbours you accept forwarded mail from — your name for each, out of
`courier.authorized_file`, and its fingerprint — and answers nobody else.

They need it because of how delivery works. A relay cannot open an envelope,
so when mail arrives from a neighbour the only sender this relay can prove is
that neighbour, and it is that identity the recipient's allow list is asked
about. A user of yours with a restricted list is therefore unreachable from
every other relay until they admit your couriers by name, which they do with
`auu allow add --courier`. You could not withhold this and still have
forwarding work for them.

It is not the disclosure the silent courier mailbox above exists to prevent.
That one was an oracle on a forward's delivery, open to a sender on any
relay that forwards here who held a fingerprint and needed no mailbox here
to use it. This route answers only identities that have one, as the post,
the stream, the knock and the channels route do.

**How much that narrows it is your `registration` setting.** With `token` or
`closed` it is the identities an administrator let in, or the ones already there.
With `open`, the default, a registered identity is anybody who asked, so your
accept-side peering is public to anyone who asks for a mailbox. One of those
identities is a neighbour's own courier, since a courier registers here in order
to forward. [1.9](#19-keeping-a-relay-private) says what that costs beside the
rest of what open registration discloses, and why the remedy is `token` rather
than a setting on this route.

There is no paging and no parameter: `relayapi.MaxCouriers`, a thousand,
bounds both the lines you may put in the file and the entries a client will
read, so the whole list is one answer. A relay with no `courier` block answers
an empty list rather than an error. It forwards nothing, and that is an
answer. A line added to or removed from the file shows up in the next answer
without a restart, as it does everywhere else the file is read.

## 2. Administering a relay

### 2.1 Who is an administrator

Whoever the relay's host says. Point `--admin-file` at a file of export lines,
one per administrator, in exactly the format a user keeps in
`authorized_peers`:

*Listing 2.1a*
```
# /etc/auu/admins
ccx2.<base64>.bunty
ccx2.<base64>.ops-oncall
```

Each administrator prints their own line with `auu id export`. This is the
`authorized_keys` model, and it has two useful consequences. The relay holds an
administrator's public key directly, so **an administrator need not be a user
of the relay at all**. There is no bootstrap problem, because the operator
writes the first line by hand.

The file must not be writable by group or others. Anyone who can write it can
appoint themselves. The relay refuses to start if the file is. It is loaded at
start, when the log says `administrators loaded count=N`. It is re-read
whenever it changes, so appointing or removing an administrator is an edit,
not a restart. Each reload is logged as `administrators reloaded count=N path=…`,
so an operator can see the relay took an edit, and see one they did not make.
A file that cannot be read after start loses nobody their access. The relay
keeps the set it last loaded and warns once, with the count it kept. Without
`--admin-file` a relay has no administrators and the whole admin API answers
403.

### 2.2 auu-admin

`auu-admin` is a separate binary from `auu`, deliberately. The privilege
boundary is visible in what is installed where, and the `connect` skill never
touches it. It reads your identity and relay from `AUU_HOME` like `auu` does,
so an administrator can keep a dedicated identity in its own home.

*Listing 2.2a*
```
auu-admin status

auu-admin mailboxes ls [--after FP] [--limit N]   # N is 1 or more; over 200 the relay answers 200
auu-admin mailboxes show FP        # queued, allow list, card, directory, channels, blocked
auu-admin mailboxes rm FP          # deregister, discarding queued mail
auu-admin mailboxes purge FP       # discard queued mail, keep the mailbox

auu-admin blocks ls
auu-admin blocks add FP --reason TEXT
auu-admin blocks rm FP

auu-admin token issue --note TEXT [--expires 168h] [--uses N] [--for FP]
auu-admin token ls [--all]
auu-admin token revoke ID
auu-admin token show TOKEN         # offline, reads a token without asking a relay
```

Read with `curl`, the relay's answer to `mailboxes show` is the mailbox
under a `mailbox` key, and its answer to a token added (`token issue`) is
the token under a `token` key: a whole answer wraps its record, so that
the answer may carry sections and the record, which is also a row in a
list, never does.

Every command takes `--json`, and `--relay NAME|URL` to choose which relay to
administer. That is a name from `auu relay ls`, or a URL. The URL may be one
your home has never joined, which is how the first administrator's machine
starts. Without it the relay is `AUU_RELAY` and then your home's default.
Destructive commands say what will go and ask, unless you pass `--yes`.

Blocking an identity stops it registering, authenticating, and receiving mail.
It deletes nothing. Purge the mailbox separately if that is what you mean.
Blocks never apply to administrators, so a mistake there cannot lock you out of
undoing it.

### 2.3 Enrolment tokens

An enrolment token is a short signed string that says who issued it, which
relay it is for, what it is for, and when it stops working:

*Listing 2.3a*
```
auu-admin token issue --note "Bob, for the protocol review" --expires 168h
```

It is signed with **your** identity key, not a key the relay holds, and then
registered with the relay in the same step. That combination is what makes the
rest work. The signature proves an administrator issued it. Registering it
is what lets the relay count its uses, revoke it, and refuse one it has never
heard of. Remove an administrator from the authorized file and every token they
ever issued stops working.

Send the token to the person joining. It is a bearer credential. Anyone
holding it can create a mailbox, so use a channel you would trust for that.
Add `--for FINGERPRINT` when you already have theirs, and then only they can
spend it.

A token has a **use**. The default, `register`, creates a mailbox. On a relay
with client certificates, somebody who already has a mailbox and wants to add
a second machine needs `--use cert`. That use is always bound to one identity:

*Listing 2.3b*
```
auu-admin token issue --use cert --for FINGERPRINT --note "Bob's desktop"
```

An identity that has a mailbox but no live certificate is not adding a
machine, it is enrolling. Either the relay began requiring certificates after
it joined, or its only certificate expired or was revoked. It enrols again
with an ordinary `register` token, `auu register --token TOKEN`. The
certificate comes with it in the same step. A live certificate on record is
what makes the next request a second machine. No path is token-free.

On their side, with nothing set up yet:

*Listing 2.3c*
```
auu enrol --name bob ccxt2.eyJpZCI6...
```

which shows them who issued it, for what, for which relay and until when. It
then asks them to confirm, creates their identity, takes the relay from the
token, and registers. With an identity already:

*Listing 2.3d*
```
auu register --token ccxt2.eyJpZCI6...
```

Either of them can read a token before acting on it with `auu token show`,
which says what use it is for.

### 2.4 Getting onto a relay from a second machine

On a relay with client certificates, copying `~/.auu` to another computer is
not enough. The identity comes with it, but each relay's `cert.json` under
`relays/<name>/` is that machine's and must not. The relay refuses the
new machine. `auu` says exactly that, and what to do:

*Listing 2.4a*
```
this relay requires a client certificate and this machine's is missing:
run 'auu register --token TOKEN' with a token from an administrator
```

Ask an administrator for `--use cert --for` your fingerprint, then:

*Listing 2.4b*
```
auu register --token ccxt2.eyJpZCI6... --label desktop
```

An ordinary `register` token is refused here, because the identity already
holds a live certificate on the first machine. The refusal says so and
names the token to ask for, with your fingerprint filled in:

*Listing 2.4c*
```
this identity already holds a live certificate on another machine, so adding
this one needs a certificate token: ask the administrator for one issued with
--use cert --for FINGERPRINT
```

The label is how that machine appears in `auu cert ls` and to an
administrator. It defaults to the hostname. Each machine's key is its own and
never leaves it, so revoking one leaves the others alone. A home on several
relays needs one certificate per relay. Add `--relay NAME` and ask for a token
from each relay's administrators.

A token authorises a mailbox. It says nothing about who is safe to talk to.
Exchanging keys with the people you will actually message is still the
out-of-band step it always was, and enrolment does not change it.

### 2.5 The audit log

Every administrative change and every enrolment writes one line, in both access
log modes:

*Listing 2.5a*
```
msg=admin action=token.issue admin=9bd6f672f1aab1b2 target=5d1f0c…  outcome=ok uses=1 not_after=2026-09-13T06:01:22Z
msg=admin action=enrol       admin=-                target=77d9de79…  outcome=ok token=5d1f0c…
msg=admin action=block.add   admin=9bd6f672f1aab1b2 target=1a2b3c4d…  outcome=ok
```

This is the operator's record of what their own administrators did, not a
record of users' traffic. That is why `access_log: "minimal"` does not turn it
off. The token string itself never appears in a log.
