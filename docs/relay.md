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
| `--max-bytes N` | `max_bytes` | 16 MiB, at most 1 GiB |
| `--streams` | `streams` | true |
| `--max-stream-bytes N` | `max_stream_bytes` | 4 GiB, 0 is unlimited |
| `--registration open\|token\|closed` | `registration` | `open`; the health answer carries the word, since it is what a name listed on this relay rests on |
| `--public-url URL` | `public_url` | none |
| `--admin-file PATH` | `admin.authorized_file` | none, no administrators |
| `--token-max-age DURATION` | `admin.token_max_age` | `720h` |
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
| `--max-inflight N` | `limits.max_inflight` | 256 |
| `--max-waiting N` | `limits.max_waiting` | 64 |
| `--knock-max-bytes N` | `limits.knock_max_bytes` | 8192, at most `max_bytes`; 0 is `max_bytes` |
| `--max-knocks-waiting N` | `limits.max_knocks_waiting` | 10, at most 1000 |
| `--knocks-per-hour N` | `limits.knocks_per_hour` | 10 |
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
shell on the host; `auu-relay --version` answers the same of a binary in
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
`tls.cert_file`, `tls.key_file` and `tls.bundle`. `"db": "relay.db"` in
`/etc/auu/relay.json` is `/etc/auu/relay.db` whether systemd or a shell
started the relay. The default when the file names no `db` at all follows
the same rule, `relay.db` and `messages` beside the settings. A path given
as a flag is the shell's, relative to the working directory as any flag is.

Use `--print-config` to see exactly what the relay resolved, paths
included. Its output is valid input for `--config`.

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
    b4/
      b49c…64 hex…/            one directory per recipient
        17                     one message, exactly the bytes that were posted
```

So `relay.db` stays small whatever the relay is carrying. A 2 GB message is
four kilobytes of database and a two gigabyte file. A completed upload is
*renamed* into place rather than copied. That is why finishing one is instant
however large it is, and why `messages_dir` must be a single filesystem.

The database also holds, per mailbox, the three documents an owner signs
and pushes — the channel directory in `directories` and `channels`, the
allow list in `allowlists`, and the card in `cards`, each the bytes the
owner signed and the signature over them, verified against the mailbox's
registered key at the push and again wherever the relay acts on one: the
allow list at every post, the card at every knock, and the directory at
every post and every stream open, `default` included. The
`channels` rows beside the directory's bytes are the relay's parse at the
push, kept for the administrator's count and for the watch's issue time;
nothing routes by them, so a row inserted or edited with the database open
changes what `auu-admin` prints and not where a message goes, and a
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
left. The name on a card is not stored a second time; the relay has no
use for it. A message row carries its kind, `envelope`, `stream` or
`knock`, the word the route it arrived by gives it and the word every
listing says beside the row; a knock is an envelope a stranger posted to
the knock route of a mailbox whose card, verified at that moment and
never read from the column, says `knocks`. A knock row carries one thing
no other row does: the fingerprint of the knocker, the one the request's
signature proved and never anything the envelope claims. It is there so
that a second knock from the same key replaces the first — which is what
makes `max_knocks_waiting` a count of knockers — and it lives exactly as
long as the row: until the owner's fetch acknowledges it, until it is
replaced, or until the mailbox goes. Beside the uploads table it is the
only place the relay records who is sending something; an operator whose
users would rather it did not can say so, and those users push a card
that takes no knocks.

An operator can list all of this, and count it, and delete it. None of it can
be read. Every file is a sealed envelope or a sealed stream. **Back up the
database and the message directory together**, or you will restore an index
pointing at mail that is not there. A relay that finds one without the other
says so at startup and repairs itself towards the database. Files with no row
are removed. Rows with no file are dropped and logged. A stream whose file
has changed length since it was stored is dropped by the same rule when its
recipient asks for it. The log carries the message id and both lengths. It
carries the mailbox only under `access_log: "full"`, since its owner is the
caller. The recipient's `auu inbox` says which message was damaged on the
relay and to ask the sender to send it again, then moves on. The one case it
will not repair is a database that knows no mailbox at all beside a directory
that holds mail, since repairing that would mean removing every message. The
database was lost. The relay refuses to start, saying so, and naming the
two remedies, restoring `relay.db` from a backup or moving the message
directory aside to start empty. The database is at this version's schema
or is refused, never migrated. One from before v0.11.0 is deleted, with
the message directory beside it. The relay recreates both at the next
start, after which every machine enrolled on it enrols again. The refusal
says so, naming both paths. One from a newer release is refused too,
naming the version it found and the one this relay understands.

### 1.2 Large messages

Above 64 KiB a client stops posting one envelope and uploads a stream. A
stream is an open that reserves the room, then one request per attempt
carrying the sealed bytes from an offset to the end. Three settings govern it:

| setting | what it does |
|---|---|
| `streams` | whether the relay accepts stream uploads at all. Turn it off and an open is refused with a 403 naming this setting |
| `max_stream_bytes` | the largest stream the relay will reserve space for, declared up front and refused before a byte is sent. `0` is unlimited, under a cap of 2^62 bytes no setting lifts |
| `max_bytes` | besides being the largest envelope a post may carry, the resume threshold: an attempt that stops short after at least this many bytes, when it was the first, leaves a partial the sender may resume once within sixty seconds; one that stops short of it, or a resumed one that stops short, leaves nothing, and the upload and its reservation go with the answer. The relay announces it at the open as `resume_threshold`, with the window as `resume_window`. A listing page follows it too: a page ends before an envelope that would take its inline bytes past `max_bytes`, admitting the first whatever its size, so a page's envelopes never exceed `max_bytes` unless the first alone does, which only one posted under a larger earlier `max_bytes` can; the health answer says the figure so a client can size what it holds of a page to this relay, and raising `max_bytes` grows every client's page with it |

The window is not a setting. It is sixty seconds from the open, and sixty
from the moment a partial is kept. Past it the relay refuses the next attempt
with a 410 that says when the upload expired and to open again. It forgets
the upload with the answer, so the reservation ends when it was promised to.
The sender's `send --resume` opens a new upload for the same sealed bytes. An
expired upload nobody touches is swept by the purge that runs every hundredth
request. The purge skips an upload mid-attempt rather than wait behind its
sender and returns to it next time. Bytes that stop coming end inside the
window too. An attempt runs under a stall deadline of sixty seconds that
every delivering read moves on. So a transfer of any length finishes while
bytes keep arriving, and a stalled one is cut and judged as an attempt that
stopped short. The download of a placed stream is served under the same
deadline turned round, moved by every write that delivers bytes. So a slow
reader is served to the end and a reader that stops is cut inside the
window. The server's five-minute read and write timeouts stand on every
other route.

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
| `post_bytes_per_hour` | posted bytes, per identity: an envelope's size, and a stream's declared size when it is opened, of which what the relay never ends up holding — the size less what it received — comes back when the upload goes unplaced | 256 MiB |
| `unauthenticated_per_minute` | registrations, key lookups and failed authentications, per source address | 30 |
| `registrations_per_hour` | registrations, per source address | 5 |
| `max_mailboxes` | mailboxes on the relay | unlimited |
| `mailbox_max_messages` | messages queued for one recipient | 1000 |
| `mailbox_max_bytes` | queued bytes for one recipient | 1 GiB |
| `relay_max_bytes` | queued bytes across the whole relay | unlimited |
| `max_open_uploads` | uploads one sender may have open at once, across every mailbox it sends to; each is a file and a reservation the relay holds for that sender, so 0, unlimited like the rest, lets one sender hold as many as it likes; at most 1000 | 4 |
| `max_inflight` | requests being handled at once | 256 |
| `max_waiting` | listings held open at once for watchers; over it the next is answered at once rather than held, and each held listing keeps an in-flight slot, so keep this well under `max_inflight` | 64 |
| `knock_max_bytes` | the largest knock envelope, on the knock route's own cap, so a stranger's one message is read under a bound of its own; 0 is `max_bytes`, since a knock is a post, and a value over `max_bytes` is refused at startup naming both | 8192 |
| `max_knocks_waiting` | knockers one mailbox holds a knock from, counted as rows the relay has whatever the owner has read. One knocker holds one row however often they knock: a second knock from a key replaces the first, so this counts knockers and one identity cannot fill it. A knock from somebody the mailbox holds none from is refused `429` at the cap, with no `Retry-After`, since the relay cannot say when the owner will fetch or remove them, and the sender's knock is not charged for it; 0 is unlimited; at most 1000, for the reason `max_open_uploads` has a ceiling | 10 |
| `knocks_per_hour` | knocks one sender may post in an hour, across every mailbox, beside the post budgets every knock is charged as a post; 0 is unlimited | 10 |

The three queue limits count a stream from the moment it is opened. What
an unfinished upload has reserved is charged against the mailbox's messages
and bytes and against the relay's total exactly as a queued message is. That
holds for an envelope posted beside it and for another stream alike. So a
sender cannot fill a mailbox to its quota under an open reservation and then
complete the stream on top. The reservation is released when the upload
completes, is abandoned, or expires.

The sender's byte budget is charged the same way at the open, with the
whole declared size, so a sender cannot open past it. But the budget
charges what the relay ends up holding, and what it never held comes back.
An upload that goes unplaced gives back its size less what the relay had
received. Unplaced means aborted, expired, purged, or an attempt that
stopped short and left nothing. A partial kept for a resume stays charged
while it is kept and gives back the rest when it expires unplaced. A placed
stream gives nothing back. An open the relay refuses after the charge, for a
full mailbox or the sender's own count, gives back the whole size. So a
refused open costs a post and no bytes. A sender whose link drops three
times on a 100 MB stream has spent 100 MB of its hour, not 300.

`max_open_uploads` bounds the count. A sender at it is refused `429 rate
limited: open uploads` with `Retry-After` set to the seconds until its
soonest upload expires. The sentence says that an unfinished upload
goes within sixty seconds of its last byte. The refusal is one the client
waits out. `auu send` sleeps the `Retry-After` and asks again. The
open that asks again meets the sender's expired uploads and lets them go,
so a sender who waited is not refused for a slot the purge had not yet
freed. An upload in flight, its bytes still arriving, holds its slot for
as long as they do, and the relay cannot say when that ends. A sender at
the cap over such uploads is asked back in a second.

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
directory check the same bounds.

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

`GET /v1/health` is exempt from all of it, so monitoring does not flap while
the relay is under attack.

The HTTP layer has bounds of its own, none of them settings:

| bound | value | what it does |
|---|---|---|
| request line and headers | 32 KiB | over it the answer is `431`, written by Go's `net/http` before the relay sees the request (it reads the block through a 4 KiB buffer, so the cut lands at 36 KiB); the largest header the protocol carries, the request signature, is about 200 bytes, and the relay refuses an auth header longer than its five fields can be before it reads one |
| body of a post | `max_bytes` + 64 KiB | the envelope with its JSON and base64 framing |
| body of a knock | `knock_max_bytes` + 64 KiB | the same framing over a knock envelope, which the handler then holds to `knock_max_bytes` itself, refusing one over it `413` naming the setting |
| body of an allow list or a channel directory | 1 MiB | two of the three owner-signed documents, sized to their own maxima on the wire — a full directory of 64 channels at every cap is 565,026 bytes as the client sends it — with the room above for a signer that indents; over it the answer is `413` naming the bytes and saying to send the document compact |
| body of every other request | 64 KiB | a card (whose document inside is held to 512 bytes besides), a registration, a certificate request, an admin token, a stream's open; none reaches a tenth of it |
| the stream `PUT` | the size the open declared | its `Content-Length` must equal what is left of that size, judged before a byte is read |
| timeouts | headers 15 s, body 5 min, response 5 min, idle 2 min | the stream routes move their own deadlines as above |

A body that declares itself over its cap is refused `413` before a byte of
it is read, the sentence naming the cap in bytes. One that arrives without
a length is cut at the cap. On every authenticated route the relay checks
what it can before the body. That is the client certificate, that the auth
header parses, and that the identity it names has a mailbox. It reads the
body only then, so a stranger's sixteen megabytes are refused unread. The
signature, which is over the body, is checked after it, the stream PUT
excepted, whose signature is over an empty body and comes before it. Every refusal before
the body closes the connection behind its answer. Those refusals are that
`413`, a `401` for a header that will not parse or an identity no mailbox
has, and a `503` from the in-flight cap. Go's `net/http` would otherwise
read up to 256 KiB of the unread body before answering on a connection it
meant to keep, and wait for a body that never came. The relay speaks
HTTP/1.1 alone. HTTP/2 is off on the listener and not offered by ALPN, so a
client that offers `h2` is answered over HTTP/1.1. Every property of the
wire above holds under the one protocol the relay's tests run.

The access log records one line per request. In the default `full` mode that
line names the verified caller and the request path, which together are who is
writing to whose mailbox. Set `access_log: "minimal"` on any relay shared
beyond one team. It logs the route (`POST /v1/mailbox/{fp}`) instead of the
path and omits the caller. That is still enough to operate the relay and to
tell an attack from ordinary traffic. One thing it does not hide, because
it is not in the log at all: a waiting knock's row names its knocker, so
the database says who has knocked at whom until that knock is fetched or
replaced. An operator whose users want no such record turns knocks off by
telling them so; a user does it themselves with a card that says no
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

The relay is given two signing keys and no more. What a copy of its disk buys
an attacker is the ability to be that one relay and to issue client
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

Set `registration` to `token` and nobody creates a mailbox without an
invitation an administrator signed. Combined with each user running
`auu allow push`, that keeps a relay to a known group. `closed` stops new
mailboxes altogether while leaving the existing ones working. In every
mode the display name a registration carries is held to the export line's
rule and refused `400` otherwise. The rule is letters, digits, `.`, `_`
and `-`, at most 64 bytes. That is because the relay serves it to every
enrolled machine and the administrator's terminal. `auu lookup` and
`auu-admin` print a name from a relay older than that rule with anything
unprintable escaped, the confirmation before a mailbox is removed included.
Every client prints a relay's refusal the same way, so a relay's own
sentences cannot drive a terminal either. A machine's certificate label is
stripped of the same characters a channel name may not hold before it is
stored.

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
